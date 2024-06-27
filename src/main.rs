use alloy::{
    consensus::TypedTransaction,
    network::{Ethereum, EthereumWallet, TransactionBuilder, TxSigner},
    primitives::{Address, U256},
    providers::{
        fillers::{FillProvider, JoinFill, WalletFiller},
        Identity, ProviderBuilder, ReqwestProvider, WalletProvider,
    },
    signers::local::PrivateKeySigner,
    sol,
    transports::http::ReqwestTransport,
};
use chrono::{TimeDelta, Utc};
use color_eyre::eyre::{bail, ensure, Result};
use ethers_signers::{LocalWallet, Signer};
use futures_util::StreamExt;
use jsonrpsee::http_client::{transport::Error as HttpError, HttpClientBuilder};
use mev_share_rpc_api::{BundleItem, FlashbotsSignerLayer, MevApiClient, SendBundleRequest};
use mev_share_sse::{Event, EventClient};
use tower::ServiceBuilder;

use std::env;
use std::str::FromStr;
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use url::Url;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    UNISWAP_V2_ROUTER,
    "src/abi/univ2router.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    UNISWAP_V2_FACTORY,
    "src/abi/univ2factory.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ERC20,
    "src/abi/erc20.json"
);

// https://docs.uniswap.org/contracts/v2/reference/smart-contracts/v2-deployments
const UNISWAP_V2_ADDRESS: &str = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
const UNISWAP_FACTORY_ADDRESS: &str = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f";
// discount we expect from the backrun trade (basis points):
const DISCOUNT_IN_BPS: u64 = 40;
// try sending a backrun bundle for this many blocks:
const BLOCKS_TO_TRY: u64 = 24;
// WETH:
const SELL_TOKEN_ADDRESS: &str = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
const SELL_TOKEN_AMOUNT: u64 = 100_000_000;
// DAI:
const BUY_TOKEN_ADDRESS: &str = "0x6b175474e89094c44da98b954eedeac495271d0f";
const BUY_TOKEN_AMOUNT_CUTOFF: u64 = SELL_TOKEN_AMOUNT * 1800;
const MEV_SHARE_EVENTS: &str = "https://mev-share.flashbots.net";
const MEV_RPC_URL: &str = "https://relay.flashbots.net:443";
const TX_GAS_LIMIT: u128 = 400_000;
const MAX_GAS_PRICE: u128 = 20;
const MAX_PRIORITY_FEE: u128 = 5;
const GWEI: u64 = 10u64.pow(9);

fn event_is_related_to_pair(event: &Event, pair_address: Address) -> bool {
    event
        .transactions
        .iter()
        .any(|tx| tx.to == Some(pair_address))
        || event
            .logs
            .iter()
            .any(|tx_log| tx_log.address == pair_address)
}

type RPCProvider = FillProvider<
    JoinFill<Identity, WalletFiller<EthereumWallet>>,
    ReqwestProvider,
    ReqwestTransport,
    Ethereum,
>;

struct Searcher {
    read_provider: ReqwestProvider,
    write_provider: RPCProvider,
    fb_client: Box<dyn MevApiClient>,
}

impl Searcher {
    fn new(executor_key: &str, fb_key: &str, rpc_url: &str, fb_rpc_url: &str) -> Result<Self> {
        let signer = PrivateKeySigner::from_str(executor_key)?;
        let signer_address = signer.address();
        let executor_wallet = EthereumWallet::from(signer);
        let write_provider = ProviderBuilder::new()
            .wallet(executor_wallet.clone())
            .on_http(Url::from_str(rpc_url)?);
        let read_provider = ProviderBuilder::new().on_http(Url::from_str(rpc_url)?);

        // The signer used to authenticate bundles
        let fb_signer = LocalWallet::from_str(fb_key)?;
        // Set up flashbots-style auth middleware
        let signing_middleware = FlashbotsSignerLayer::new(fb_signer);
        let service_builder = ServiceBuilder::new()
            // map signer errors to http errors
            .map_err(HttpError::Http)
            .layer(signing_middleware);

        // Set up the rpc client
        let fb_client = Box::new(
            HttpClientBuilder::default()
                .set_middleware(service_builder)
                .build(MEV_RPC_URL)?,
        );

        Ok(Self {
            read_provider,
            write_provider,
            fb_client,
        })
    }

    fn read_provider(&self) -> &ReqwestProvider {
        &self.read_provider
    }

    fn write_provider(&self) -> &RPCProvider {
        &self.write_provider
    }

    fn signer_address(&self) -> Address {
        self.write_provider.wallet().default_signer().address()
    }

    async fn approve_token_to_router(
        &self,
        token_address: Address,
        router_address: Address,
    ) -> Result<()> {
        // https://eips.ethereum.org/EIPS/eip-20
        let token_contract = ERC20::new(token_address, &self.write_provider);
        // TODO join two futs
        let ERC20::allowanceReturn { _0: allowance } = token_contract
            .allowance(self.signer_address(), router_address)
            .call()
            .await?;
        let ERC20::balanceOfReturn { _0: balance } = token_contract
            .balanceOf(self.signer_address())
            .call()
            .await?;
        ensure!(
            balance > U256::ZERO,
            "no token balance for {:?}",
            self.signer_address()
        );
        ensure!(allowance < balance, "token already approved");
        token_contract
            .approve(router_address, U256::from(SELL_TOKEN_AMOUNT))
            .call()
            .await?;
        Ok(())
    }

    async fn get_buy_token_amount_with_extra(&self) -> Result<U256> {
        let router_contract =
            UNISWAP_V2_ROUTER::new(Address::from_str(UNISWAP_V2_ADDRESS)?, &self.read_provider);
        let now = Utc::now();
        let time_in_force_seconds = now + TimeDelta::seconds(60);
        // https://docs.uniswap.org/contracts/v2/reference/smart-contracts/router-02#swapexacttokensfortokens
        let UNISWAP_V2_ROUTER::swapExactTokensForTokensReturn { amounts } = router_contract
            .swapExactTokensForTokens(
                U256::from(SELL_TOKEN_AMOUNT),
                U256::from(1u8),
                vec![
                    Address::from_str(SELL_TOKEN_ADDRESS)?,
                    Address::from_str(BUY_TOKEN_ADDRESS)?,
                ],
                self.signer_address(),
                time_in_force_seconds.timestamp().try_into()?,
            )
            .call()
            .await?;
        let normal_output_amount = amounts[1];
        let extra_output_amount = normal_output_amount
            * (U256::from(10000) + U256::from(DISCOUNT_IN_BPS))
            / U256::from(10000);
        Ok(extra_output_amount)
    }

    async fn get_signed_backrun_tx(&self, output_amount: U256) -> Result<Vec<u8>> {
        let router_contract =
            UNISWAP_V2_ROUTER::new(Address::from_str(UNISWAP_V2_ADDRESS)?, &self.write_provider);
        let now = Utc::now();
        let time_in_force_seconds = now + TimeDelta::seconds(60);
        let tx_builder = router_contract
            .swapExactTokensForTokens(
                U256::from(SELL_TOKEN_AMOUNT),
                output_amount,
                vec![
                    Address::from_str(SELL_TOKEN_ADDRESS)?,
                    Address::from_str(BUY_TOKEN_ADDRESS)?,
                ],
                self.signer_address(),
                time_in_force_seconds.timestamp().try_into()?,
            )
            .chain_id(1)
            .gas(TX_GAS_LIMIT)
            .max_fee_per_gas(MAX_GAS_PRICE)
            .max_priority_fee_per_gas(MAX_PRIORITY_FEE);
        let tx = tx_builder.as_ref().clone().build_typed_tx();
        let Ok(TypedTransaction::Eip1559(mut tx)) = tx else {
            bail!("expect tx in EIP1559")
        };
        let signer = self
            .write_provider
            .wallet()
            .signer_by_address(self.signer_address())
            .expect("signer was provided");

        let signature = signer.sign_transaction(&mut tx).await?;
        let mut buf = vec![];
        tx.encode_with_signature(&signature, &mut buf, false);
        Ok(buf)
    }

    async fn backrun_attempt(
        &self,
        current_block_number: U256,
        pending_tx_hash: [u8; 32],
    ) -> Result<()> {
        let mut output_amount = self.get_buy_token_amount_with_extra().await?;
        let cutoff = U256::from(BUY_TOKEN_AMOUNT_CUTOFF);
        if output_amount < cutoff {
            info!("Even with extra amount, not enough BUY token: {output_amount}. Setting to amount cut-off ({cutoff})");
            output_amount = cutoff;
        }
        let signed_tx_bytes = self.get_signed_backrun_tx(output_amount).await?;

        let bundle = SendBundleRequest {
            bundle_body: vec![
                BundleItem::Hash {
                    hash: pending_tx_hash.into(),
                },
                BundleItem::Tx {
                    tx: signed_tx_bytes.into(),
                    can_revert: false,
                },
            ],
            ..Default::default()
        };

        // Send bundle
        let resp = self.fb_client.send_bundle(bundle).await;

        // let sim_res = client.sim_bundle(bundle, Default::default()).await;
        // println!("Got a simulation response: {:?}", sim_res);
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    dotenvy::dotenv()?;
    color_eyre::install()?;
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let private_key = env::var("EXECUTOR_KEY")?;
    let fb_key = env::var("FB_REPUTATION_KEY")?;
    let rpc_url = env::var("RPC_URL")?;
    let searcher = Searcher::new(&private_key, &fb_key, &rpc_url, MEV_RPC_URL)?;

    //info!("mev-share auth address: {}", authSigner.address)
    info!("executor address: {}", searcher.signer_address());

    let client = EventClient::default();
    let mut stream = client.events(MEV_SHARE_EVENTS).await?;
    info!("subscribed to {}", stream.endpoint());

    let factory_contract = UNISWAP_V2_FACTORY::new(
        Address::from_str(UNISWAP_FACTORY_ADDRESS)?,
        searcher.read_provider(),
    );

    let sell_address = Address::from_str(SELL_TOKEN_ADDRESS)?;
    let buy_address = Address::from_str(BUY_TOKEN_ADDRESS)?;

    // https://docs.uniswap.org/contracts/v2/reference/smart-contracts/factory#getpair
    let UNISWAP_V2_FACTORY::getPairReturn { pair: pair_address } = factory_contract
        .getPair(sell_address, buy_address)
        .call()
        .await?;
    ensure!(
        pair_address != Address::ZERO,
        "pair address should be non-zero"
    );
    info!("pair address: {}", pair_address);
    // searcher
    //     .approve_token_to_router(
    //         sell_address,
    //         Address::from_str(UNISWAP_V2_ADDRESS)?,
    //     )
    //     .await?;
    while let Some(event) = stream.next().await {
        if let Ok(event) = event {
            if !event_is_related_to_pair(&event, pair_address) {
                info!("skipping tx: {}", event.hash);
                continue;
            }
            info!("It's a match: {}", event.hash);
            break;
        }
    }

    Ok(())
}
