use crate::selector::{DeviceSelectorArgs, resolve_device};

pub async fn run(selector: DeviceSelectorArgs) -> anyhow::Result<()> {
    let resolved = resolve_device(&selector)?;

    if let Some(record) = resolved.record {
        println!("device id: {}", record.device_id);
        println!("manufacturer: {}", record.manufacturer_id);
        println!("model: {}", record.model_id);
        println!("hardware rev: {}", record.hardware_rev);
        println!("firmware rev: {}", record.firmware_rev);
        println!("alpine version: {}", record.alpine_version);
        println!("address: {}", resolved.addr);
    } else {
        println!("identity target: {}", resolved.addr);
    }

    Ok(())
}
