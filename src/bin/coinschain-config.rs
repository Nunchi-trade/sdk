use clap::Parser;
use commonware_codec::Encode;
use commonware_consensus::simplex::scheme::bls12381_threshold::vrf as bls12381_threshold;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, certificate::mocks::Fixture};
use commonware_formatting::hex;
use nunchi_sdk::coinschain::{Config, Peers, NAMESPACE};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value_t = 4)]
    validators: u32,
    #[arg(long, default_value = ".devnet/coinschain")]
    output: PathBuf,
    #[arg(long, default_value_t = 7)]
    seed: u64,
    #[arg(long, default_value_t = 30303)]
    p2p_port: u16,
    #[arg(long, default_value_t = 18545)]
    rpc_port: u16,
    #[arg(long, default_value_t = 19600)]
    metrics_port: u16,
    #[arg(long)]
    docker: bool,
}

fn main() {
    let args = Args::parse();
    assert!(args.validators > 0, "validators must be greater than zero");

    fs::create_dir_all(&args.output).expect("failed to create output directory");
    let mut rng = StdRng::seed_from_u64(args.seed);
    let Fixture {
        participants,
        private_keys,
        schemes,
        ..
    } = bls12381_threshold::fixture::<MinSig, _>(&mut rng, NAMESPACE, args.validators);

    let mut addresses = HashMap::new();
    for (index, public_key) in participants.iter().enumerate() {
        let ip = if args.docker {
            IpAddr::V4(Ipv4Addr::new(172, 28, 0, 10 + index as u8))
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let port = if args.docker {
            args.p2p_port
        } else {
            args.p2p_port + index as u16
        };
        addresses.insert(public_key.to_string(), SocketAddr::new(ip, port));
    }
    let peers = Peers { addresses };
    write_yaml(args.output.join("peers.yml"), &peers);

    for (index, ((private_key, scheme), public_key)) in private_keys
        .iter()
        .zip(schemes.iter())
        .zip(participants.iter())
        .enumerate()
    {
        let bootstrappers = participants
            .iter()
            .filter(|candidate| *candidate != public_key)
            .take(1)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let config = Config {
            private_key: hex(&private_key.encode()),
            share: hex(&scheme
                .share()
                .expect("scheme should include share")
                .encode()),
            polynomial: hex(&scheme.polynomial().encode()),
            port: if args.docker {
                args.p2p_port
            } else {
                args.p2p_port + index as u16
            },
            rpc_port: if args.docker {
                args.rpc_port
            } else {
                args.rpc_port + index as u16
            },
            metrics_port: if args.docker {
                args.metrics_port
            } else {
                args.metrics_port + index as u16
            },
            directory: if args.docker {
                "/data".to_string()
            } else {
                args.output
                    .join(format!("storage/node{index}"))
                    .to_string_lossy()
                    .to_string()
            },
            worker_threads: 2,
            blocking_threads: 64,
            log_level: "INFO".to_string(),
            local: true,
            bootstrappers,
            message_backlog: 1024,
            mailbox_size: 1024,
            deque_size: 1024,
            signature_threads: 2,
        };
        write_yaml(args.output.join(format!("node{index}.yml")), &config);
    }

    if args.docker {
        write_compose(&args);
    }
}

fn write_yaml<T: serde::Serialize>(path: PathBuf, value: &T) {
    let encoded = serde_yaml::to_string(value).expect("failed to encode YAML");
    fs::write(path, encoded).expect("failed to write YAML");
}

fn write_compose(args: &Args) {
    let mut compose = String::new();
    line(&mut compose, "services:");
    for index in 0..args.validators {
        line(&mut compose, format!("  node{index}:"));
        line(&mut compose, "    build:");
        line(&mut compose, "      context: ../..");
        line(&mut compose, "      dockerfile: Dockerfile.coinschain");
        line(&mut compose, "    image: nunchi-coinschain:local");
        line(
            &mut compose,
            format!(
                "    command: [\"--config\", \"/config/node{index}.yml\", \"--peers\", \"/config/peers.yml\"]"
            ),
        );
        line(&mut compose, "    volumes:");
        line(
            &mut compose,
            format!("      - ./node{index}.yml:/config/node{index}.yml:ro"),
        );
        line(&mut compose, "      - ./peers.yml:/config/peers.yml:ro");
        line(&mut compose, format!("      - node{index}-data:/data"));
        line(&mut compose, "    ports:");
        line(
            &mut compose,
            format!(
                "      - \"{}:{}\"",
                args.rpc_port + index as u16,
                args.rpc_port
            ),
        );
        line(
            &mut compose,
            format!(
                "      - \"{}:{}\"",
                args.metrics_port + index as u16,
                args.metrics_port
            ),
        );
        line(&mut compose, "    networks:");
        line(&mut compose, "      coinschain:");
        line(
            &mut compose,
            format!("        ipv4_address: 172.28.0.{}", 10 + index),
        );
    }
    line(&mut compose, "networks:");
    line(&mut compose, "  coinschain:");
    line(&mut compose, "    ipam:");
    line(&mut compose, "      config:");
    line(&mut compose, "        - subnet: 172.28.0.0/24");
    line(&mut compose, "volumes:");
    for index in 0..args.validators {
        line(&mut compose, format!("  node{index}-data:"));
    }
    fs::write(args.output.join("docker-compose.yml"), compose).expect("failed to write compose");
}

fn line(out: &mut String, value: impl AsRef<str>) {
    out.push_str(value.as_ref());
    out.push('\n');
}
