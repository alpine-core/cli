use crate::selector::{DeviceSelectorArgs, resolve_device};

pub async fn run(selector: DeviceSelectorArgs) -> anyhow::Result<()> {
    let resolved = resolve_device(&selector)?;

    if let Some(record) = resolved.record {
        println!(
            "pinging {} ({}) at {}",
            record.device_id, record.manufacturer_id, resolved.addr
        );
    } else {
        println!("pinging {}", resolved.addr);
    }

    Ok(())
}
