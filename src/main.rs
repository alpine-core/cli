use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use alpine_protocol_cli::{
    commands::{conformance, discover, handshake, identity, ping, session, status, stream},
    netinfo,
    selector::DeviceSelectorArgs,
};
use alpine_protocol_sdk::AlpineSdkError;
use anyhow::anyhow;

#[derive(Parser)]
#[command(name = "alpine")]
#[command(about = "ALPINE protocol CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

const DEFAULT_DISCOVERY_ADDR: &str = "255.255.255.255:9455";

#[derive(Subcommand)]
enum Commands {
    Discover(discover::DiscoverArgs),
    Conformance(conformance::ConformanceArgs),
    Handshake(handshake::HandshakeArgs),
    Ping(DeviceSelectorArgs),
    Status(DeviceSelectorArgs),
    Identity(DeviceSelectorArgs),
    Session {
        #[command(subcommand)]
        command: session::SessionCommand,
    },
    Stream {
        #[command(subcommand)]
        command: StreamCommands,
    },
}

#[derive(Subcommand)]
enum StreamCommands {
    Test(stream::test::StreamTestArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    netinfo::log_local_interfaces();
    if let Ok(addr) = DEFAULT_DISCOVERY_ADDR.parse() {
        netinfo::log_udp_route_hint(addr);
    }

    match cli.command {
        Commands::Discover(args) => {
            let default_remote = DEFAULT_DISCOVERY_ADDR.parse()?;
            discover::run(args, default_remote).await?;
        }
        Commands::Conformance(args) => {
            conformance::run(args).await?;
        }
        Commands::Handshake(args) => {
            handshake::run(args).await.map_err(map_handshake_error)?;
        }
        Commands::Ping(selector) => {
            ping::run(selector).await?;
        }
        Commands::Status(selector) => {
            status::run(selector).await?;
        }
        Commands::Identity(selector) => {
            identity::run(selector).await?;
        }
        Commands::Session { command } => match command {
            session::SessionCommand::List => session::list()?,
            session::SessionCommand::Clear(clear_args) => session::clear(clear_args)?,
        },
        Commands::Stream { command } => match command {
            StreamCommands::Test(selector) => {
                stream::test::run(selector).await?;
            }
        },
    }

    Ok(())
}

fn map_handshake_error(err: AlpineSdkError) -> anyhow::Error {
    match err {
        AlpineSdkError::HandshakeAlreadyInProgress => anyhow!(
            "Handshake already in progress. Run `alpine session clear --id <device>` if you need to reset."
        ),
        AlpineSdkError::MissingClientNonce => anyhow!(
            "Missing cached client_nonce. Run `alpine discover` before attempting handshake."
        ),
        AlpineSdkError::InvalidPhaseTransition(detail) => {
            anyhow!(format!("Invalid handshake phase transition: {}", detail))
        }
        AlpineSdkError::DiscoveryAfterHandshake => {
            anyhow!("Discovery is not allowed once a handshake has begun.")
        }
        other => anyhow!(other.to_string()),
    }
}
