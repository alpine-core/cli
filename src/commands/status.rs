use crate::selector::{DeviceSelectorArgs, resolve_device};

pub async fn run(selector: DeviceSelectorArgs) -> anyhow::Result<()> {
    let resolved = resolve_device(&selector)?;

    if let Some(record) = resolved.record {
        println!("device: {} ({})", record.device_id, record.manufacturer_id);
        println!("model: {}", record.model_id);
        println!("firmware: {}", record.firmware_rev);
        println!("last seen (epoch): {}", record.last_seen);
        println!("address: {}", resolved.addr);
    } else {
        println!("status target: {}", resolved.addr);
    }

    Ok(())
}
