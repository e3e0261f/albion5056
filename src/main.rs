use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device};
use std::collections::HashMap;

#[derive(Debug, Clone)]
enum PhotonValue {
    Null,
    Byte(u8),
    Bool(bool),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(String),
    ByteArray(Vec<u8>),
    IntArray(Vec<i32>),
    StringArray(Vec<String>),
    ObjectArray(Vec<PhotonValue>),
    Dictionary(Vec<(PhotonValue, PhotonValue)>),
    Unknown(u8),
}

struct FragmentBuffer {
    total_length: usize,
    bytes_received: usize,
    data: Vec<u8>,
}

struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn read_u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn read_u16_be(&mut self) -> Option<u16> {
        let s = self.buf.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        let arr: [u8; 2] = s.try_into().ok()?;
        Some(u16::from_be_bytes(arr))
    }
    fn read_i16_be(&mut self) -> Option<i16> {
        let s = self.buf.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        let arr: [u8; 2] = s.try_into().ok()?;
        Some(i16::from_be_bytes(arr))
    }
    fn read_u32_be(&mut self) -> Option<u32> {
        let s = self.buf.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        let arr: [u8; 4] = s.try_into().ok()?;
        Some(u32::from_be_bytes(arr))
    }
    fn read_i32_be(&mut self) -> Option<i32> {
        let s = self.buf.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        let arr: [u8; 4] = s.try_into().ok()?;
        Some(i32::from_be_bytes(arr))
    }
    fn read_i64_be(&mut self) -> Option<i64> {
        let s = self.buf.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        let arr: [u8; 8] = s.try_into().ok()?;
        Some(i64::from_be_bytes(arr))
    }
    fn read_f32_be(&mut self) -> Option<f32> {
        let s = self.buf.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        let arr: [u8; 4] = s.try_into().ok()?;
        Some(f32::from_be_bytes(arr))
    }
    fn read_f64_be(&mut self) -> Option<f64> {
        let s = self.buf.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        let arr: [u8; 8] = s.try_into().ok()?;
        Some(f64::from_be_bytes(arr))
    }
    fn read_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(s)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // 参数 1: 网卡名 ("default" 或具体网卡名如 "wlp8s0", "dae0")
    let iface_arg = args.get(1).map(|s| s.as_str()).unwrap_or("default");
    // 参数 2: 过滤级别 0~9 (默认 1: 过滤移动，翻译其余所有包)
    let filter_level: u8 = args
        .get(2)
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(1)
        .min(9);

    let devices = Device::list()?;
    println!("正在扫描可用网络接口...");
    for (i, dev) in devices.iter().enumerate() {
        println!("[{}] {} - {:?}", i, dev.name, dev.desc);
    }

    let main_device = if iface_arg != "default" {
        devices
            .into_iter()
            .find(|d| d.name == iface_arg)
            .ok_or_else(|| format!("未找到指定的网卡: {}", iface_arg))?
    } else {
        Device::lookup()?.ok_or("未找到默认网卡")?
    };

    println!(
        "\n正在监听网卡: {} | 当前过滤级别: {} (0=全量含移动, 1=过滤移动, 9=最严格)",
        main_device.name, filter_level
    );
    println!("用法: sudo ./albion-loot-logger [网卡名|default] [过滤级别 0-9]\n");

    let mut cap = Capture::from_device(main_device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .open()?;

    cap.filter("udp port 5056", true)?;
    println!("过滤器 'udp port 5056' 已激活，开始实时翻译封包...\n");

    let mut fragments: HashMap<i32, FragmentBuffer> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        if let Ok(sliced) = SlicedPacket::from_ethernet(packet.data) {
            if let (Some(NetSlice::Ipv4(_)), Some(TransportSlice::Udp(udp))) =
                (sliced.net, sliced.transport)
            {
                if udp.source_port() == 5056 || udp.destination_port() == 5056 {
                    parse_photon_packet(udp.payload(), &mut fragments, filter_level);
                }
            }
        }
    }

    Ok(())
}

fn parse_photon_packet(
    payload: &[u8],
    fragments: &mut HashMap<i32, FragmentBuffer>,
    filter_level: u8,
) {
    let mut r = ByteReader::new(payload);
    if r.remaining() < 12 {
        return;
    }

    let _peer_id = r.read_u16_be().unwrap();
    let flags = r.read_u8().unwrap();
    let command_count = r.read_u8().unwrap();
    let _timestamp = r.read_u32_be().unwrap();
    let _challenge = r.read_i32_be().unwrap();

    if flags == 0x01 {
        return;
    }

    for _ in 0..command_count {
        if r.remaining() < 12 {
            break;
        }
        let cmd_type = r.read_u8().unwrap();
        let _channel_id = r.read_u8().unwrap();
        let _cmd_flags = r.read_u8().unwrap();
        let _reserved = r.read_u8().unwrap();
        let cmd_len = r.read_i32_be().unwrap() as usize;
        let _reliable_seq_num = r.read_i32_be().unwrap();

        if cmd_len < 12 || r.remaining() < cmd_len - 12 {
            break;
        }

        let cmd_data = r.read_slice(cmd_len - 12).unwrap();

        match cmd_type {
            6 | 7 => {
                let msg_slice = if cmd_type == 7 && cmd_data.len() > 4 {
                    cmd_data.get(4..).unwrap_or(&[])
                } else {
                    cmd_data
                };
                handle_photon_message(msg_slice, filter_level);
            }
            8 => {
                let mut fr = ByteReader::new(cmd_data);
                if fr.remaining() >= 20 {
                    let start_seq = fr.read_i32_be().unwrap();
                    let _frag_count = fr.read_i32_be().unwrap();
                    let _frag_num = fr.read_i32_be().unwrap();
                    let total_len = fr.read_i32_be().unwrap() as usize;
                    let frag_offset = fr.read_i32_be().unwrap() as usize;
                    let chunk = fr.read_slice(fr.remaining()).unwrap_or(&[]);

                    if total_len > 0
                        && total_len < 1024 * 1024
                        && frag_offset + chunk.len() <= total_len
                    {
                        let entry = fragments
                            .entry(start_seq)
                            .or_insert_with(|| FragmentBuffer {
                                total_length: total_len,
                                bytes_received: 0,
                                data: vec![0u8; total_len],
                            });

                        if let Some(dst) =
                            entry.data.get_mut(frag_offset..frag_offset + chunk.len())
                        {
                            dst.copy_from_slice(chunk);
                            entry.bytes_received += chunk.len();
                        }

                        if entry.bytes_received >= entry.total_length {
                            if let Some(completed) = fragments.remove(&start_seq) {
                                handle_photon_message(&completed.data, filter_level);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn handle_photon_message(msg: &[u8], filter_level: u8) {
    let mut r = ByteReader::new(msg);
    let magic = match r.read_u8() {
        Some(m) => m,
        None => return,
    };
    if magic != 0xF3 {
        return;
    }

    let msg_type = match r.read_u8() {
        Some(t) => t,
        None => return,
    };
    let code = match r.read_u8() {
        Some(c) => c,
        None => return,
    };

    let kind_label = match msg_type {
        0x02 => "客户端请求 OperationRequest",
        0x03 => {
            // 跳过 ReturnCode (2字节) 和 DebugMessage 类型标志 (1字节)
            if r.read_slice(3).is_none() {
                return;
            }
            "服务器响应 OperationResponse"
        }
        0x04 => "服务器事件 EventData",
        _ => return,
    };

    let payload = r.read_slice(r.remaining()).unwrap_or(&[]);

    if let Some(params) = parse_parameter_table(payload) {
        let albion_id = extract_int(&params, 252)
            .or_else(|| extract_int(&params, 253))
            .unwrap_or(code as i32);

        if should_filter_out(filter_level, msg_type, albion_id, &params) {
            return;
        }

        if msg_type == 0x04 && albion_id == 3 {
            print_move_event(&params);
            return;
        }

        println!("------------------------------------------");
        println!(
            "[{}] 业务ID: {} (原始Code: {}) | 参数个数: {}",
            kind_label,
            albion_id,
            code,
            params.len()
        );

        let mut keys: Vec<&u8> = params.keys().collect();
        keys.sort();
        for k in keys {
            let tag = match *k {
                252 => " [Albion事件ID]",
                253 => " [Albion操作ID]",
                _ => "",
            };
            if let Some(val) = params.get(k) {
                println!("  Key {:>3}{}: {:?}", k, tag, val);
            }
        }
    } else if filter_level == 0 {
        let preview_len = payload.len().min(32);
        let preview = payload.get(..preview_len).unwrap_or(&[]);
        println!(
            "[未解析字典 {}] Code: {} | 长度: {} | HEX: {:02X?}",
            kind_label,
            code,
            payload.len(),
            preview
        );
    }
}

fn should_filter_out(
    level: u8,
    msg_type: u8,
    albion_id: i32,
    params: &HashMap<u8, PhotonValue>,
) -> bool {
    if level == 0 {
        return false;
    }
    if level >= 1 && msg_type == 0x04 && albion_id == 3 {
        return true;
    }
    if level >= 2 && matches!(albion_id, 1 | 2 | 4 | 5) {
        return true;
    }
    if level >= 3 && (6..=9).contains(&albion_id) {
        return true;
    }
    if level >= 4 && (10..=25).contains(&albion_id) {
        return true;
    }
    let string_count = params
        .values()
        .filter(|v| matches!(v, PhotonValue::String(s) if !s.is_empty()))
        .count();
    let has_array = params.values().any(|v| {
        matches!(
            v,
            PhotonValue::IntArray(_)
                | PhotonValue::StringArray(_)
                | PhotonValue::ObjectArray(_)
                | PhotonValue::ByteArray(_)
        )
    });
    if level >= 5 && string_count == 0 && !has_array {
        return true;
    }
    if level >= 6 && string_count == 0 {
        return true;
    }
    if level >= 7 && msg_type != 0x04 {
        return true;
    }
    let int_count = params
        .values()
        .filter(|v| matches!(v, PhotonValue::Int(_) | PhotonValue::Short(_)))
        .count();
    if level >= 8 && !(string_count >= 1 && int_count >= 3) {
        return true;
    }
    if level >= 9 && !(string_count >= 2 && int_count >= 3) {
        return true;
    }
    false
}
fn print_move_event(params: &HashMap<u8, PhotonValue>) {
    let entity_id = extract_int(params, 0).unwrap_or(-1);
    if let Some(PhotonValue::ByteArray(bytes)) = params.get(&1) {
        if let (Some(xb), Some(yb)) = (bytes.get(9..13), bytes.get(13..17)) {
            if let (Ok(xa), Ok(ya)) = (xb.try_into(), yb.try_into()) {
                let x = f32::from_le_bytes(xa);
                let y = f32::from_le_bytes(ya);
                println!(
                    "[角色移动 Event 3] 实体ID: {:>8} | 坐标: ({:>7.2}, {:>7.2}) | 原始字节长: {}",
                    entity_id,
                    x,
                    y,
                    bytes.len()
                );
                return;
            }
        }
    }
    println!("[角色移动 Event 3] 参数: {:?}", params);
}
fn extract_int(params: &HashMap<u8, PhotonValue>, key: u8) -> Option<i32> {
    match params.get(&key) {
        Some(PhotonValue::Int(v)) => Some(*v),
        Some(PhotonValue::Short(v)) => Some(*v as i32),
        Some(PhotonValue::Byte(v)) => Some(*v as i32),
        _ => None,
    }
}
fn parse_parameter_table(data: &[u8]) -> Option<HashMap<u8, PhotonValue>> {
    let mut r = ByteReader::new(data);
    let count = r.read_u16_be()?;
    let mut map = HashMap::with_capacity(count as usize);
    for _ in 0..count {
        let key = r.read_u8()?;
        let val = read_photon_value(&mut r)?;
        map.insert(key, val);
    }
    Some(map)
}
fn read_photon_value(r: &mut ByteReader) -> Option<PhotonValue> {
    let type_code = r.read_u8()?;
    read_photon_value_by_type(r, type_code)
}
fn read_photon_value_by_type(r: &mut ByteReader, type_code: u8) -> Option<PhotonValue> {
    match type_code {
        0 | 42 => Some(PhotonValue::Null),
        98 => Some(PhotonValue::Byte(r.read_u8()?)),
        111 => Some(PhotonValue::Bool(r.read_u8()? != 0)),
        107 => Some(PhotonValue::Short(r.read_i16_be()?)),
        105 => Some(PhotonValue::Int(r.read_i32_be()?)),
        108 => Some(PhotonValue::Long(r.read_i64_be()?)),
        102 => Some(PhotonValue::Float(r.read_f32_be()?)),
        100 => Some(PhotonValue::Double(r.read_f64_be()?)),
        115 => {
            let len = r.read_u16_be()? as usize;
            let buf = r.read_slice(len)?;
            Some(PhotonValue::String(
                String::from_utf8_lossy(buf).into_owned(),
            ))
        }
        120 => {
            let len = r.read_i32_be()? as usize;
            if len > 1024 * 1024 {
                return None;
            }
            let buf = r.read_slice(len)?;
            Some(PhotonValue::ByteArray(buf.to_vec()))
        }
        110 => {
            let len = r.read_i32_be()? as usize;
            if len > 100_000 {
                return None;
            }
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(r.read_i32_be()?);
            }
            Some(PhotonValue::IntArray(arr))
        }
        97 => {
            let len = r.read_u16_be()? as usize;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                let s_len = r.read_u16_be()? as usize;
                let buf = r.read_slice(s_len)?;
                arr.push(String::from_utf8_lossy(buf).into_owned());
            }
            Some(PhotonValue::StringArray(arr))
        }
        121 => {
            let len = r.read_u16_be()? as usize;
            let elem_type = r.read_u8()?;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(read_photon_value_by_type(r, elem_type)?);
            }
            Some(PhotonValue::ObjectArray(arr))
        }
        122 => {
            let len = r.read_u16_be()? as usize;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(read_photon_value(r)?);
            }
            Some(PhotonValue::ObjectArray(arr))
        }
        68 => {
            let key_type = r.read_u8()?;
            let val_type = r.read_u8()?;
            let len = r.read_u16_be()? as usize;
            let mut entries = Vec::with_capacity(len);
            for _ in 0..len {
                let k = if key_type == 0 || key_type == 42 {
                    read_photon_value(r)?
                } else {
                    read_photon_value_by_type(r, key_type)?
                };
                let v = if val_type == 0 || val_type == 42 {
                    read_photon_value(r)?
                } else {
                    read_photon_value_by_type(r, val_type)?
                };
                entries.push((k, v));
            }
            Some(PhotonValue::Dictionary(entries))
        }
        _ => Some(PhotonValue::Unknown(type_code)),
    }
}
