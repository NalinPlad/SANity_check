#[macro_use]
extern crate rocket;
use std::{collections::HashMap, io::Write, net::ToSocketAddrs};
use openssl::ssl::{SslConnector, SslMethod};
use rocket::{serde::{json::Json, Serialize}, tokio::sync::RwLock, State};
use rocket_cors::{AllowedOrigins, CorsOptions};
use async_recursion::async_recursion;


#[derive(Serialize)]
struct StatusMessage {
    message: String
}

#[derive(Serialize)]
struct CacheInfo {
    num_entries: usize,
}


#[derive(Serialize, Clone)]
struct SANEntry {
    host: String,
    success: bool,
    children: Vec<SANEntry>
}

struct SANCache {
    data: RwLock<HashMap<String, SANCacheItem>>
}

struct SANCacheItem {
    cache_expire: u64,
    entry: SANEntry
}

#[async_recursion]
async fn openssl_san_recursive(url: &str, parent_node: &mut SANEntry, found_vec: &mut Vec<String>, connector: &SslConnector, cache: &State<SANCache>) {


    // if found_vec.contains(&url.to_string()) {
    //     return;
    // }

    println!("* {}", url);

    let mut url = url.to_string();

    if url.contains("*") && !found_vec.contains(&url.to_string().replace("*.", "")) {
        url = url.replace("*.", "");
        println!("following wildcard, {}", url);
    }

    let url = url.as_str();

    let cache_read = cache.data.read().await;

    if cache_read.contains_key(url) {
        let cache_item = cache_read.get(url).unwrap();
        println!("Reading from cache...");
        // if cache_item.cache_expire TODO
        return parent_node.children.push(cache_item.entry.clone());
    }

    
    // check if its a regular host url, not a wildcard
    // if url.contains("*") {
    //TODO: this causes something wierd
    // }
        
    drop(cache_read);

    
    let mut tcp_url = String::from(url);
    tcp_url.push_str(":443");

    let tcp_url_soc = tcp_url.to_socket_addrs();

    if tcp_url_soc.is_err() {
        parent_node.success = false;
        println!("Failed to resolve {}", tcp_url);
        return;
    }

    let tcp_url = tcp_url_soc.unwrap().next().unwrap();
    
    println!("Starting scan for {}", url);
    // TODO: configurable timeout
    let stream = std::net::TcpStream::connect_timeout(&tcp_url, std::time::Duration::from_millis(1000));


    if stream.is_err() {
        parent_node.success = false;
        return;
    }

    let stream = connector.connect(&url, stream.unwrap());

    if stream.is_err() {
        parent_node.success = false;
        println!("Failed to connect to {}", url);
        return;
    }

    let mut stream = stream.unwrap();
    
    // Perform the handshake
    let _ = stream.write_all(&[]).unwrap();
    
    let cert = stream.ssl().peer_certificate().ok_or("no cert").unwrap();
    
    let x509 = openssl::x509::X509::from_der(&cert.to_der().unwrap()).unwrap();

    for ent in x509.subject_alt_names().unwrap().iter() {
        if !found_vec.contains(&ent.dnsname().unwrap().to_string()) {
            let san = ent.dnsname().unwrap();
    
            let child = SANEntry {
                host: san.to_string(),
                success: true,
                children: vec![]
            };
    
            found_vec.push(ent.dnsname().unwrap().to_string());
            parent_node.children.push(child);
            
        }
        
        
    }
    
    for mut child in parent_node.children.iter_mut() {
        openssl_san_recursive(&child.host.clone(), &mut child, found_vec, &connector, cache).await;
    }

    println!("Finished scan for {}", url);

    // let mut cache_write = cache.data.write().await;

    // println!("Inserting {} into cache...", url);

    // cache_write.insert(url.to_string(), SANCacheItem{
    //     cache_expire: 0,
    //     entry: parent_node.clone()
    // });


    
}

#[get("/query/<url>")]
async fn get_san(url: &str, cache: &State<SANCache>) -> Result<Json<SANEntry>, String> {
    // url decode the parameter
    let url = urlencoding::decode(url).unwrap().into_owned();

    println!("=== Received request for {}", url);

    // println!("Getting cache read lock...");
    
    // let cache_read = cache.data.read().await;

    // println!("Got cache read lock");
    
    // if cache_read.contains_key(&url) {
    //     let cache_item = cache_read.get(&url).unwrap();
    //     // if cache_item.cache_expire TODO
    //     println!("Reading from cache...");
    //     return Ok(Json(cache_item.entry.clone()));
    // }

    // drop(cache_read);

    // println!("Cache miss, scanning...");

    // TODO: move cache to openssl function to make it recursively cache things, will be orders of magnitude faster

    let mut root_output = SANEntry {
        host: url.to_string(),
        success: true,
        children: vec![]
    };

    let mut found_hosts = vec![];
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    openssl_san_recursive(&url, &mut root_output, &mut found_hosts, &connector, cache).await;

    println!("Writing to cache...");

    println!("Getting cache write lock...");

    let mut cache_write = cache.data.write().await;

    println!("Got cache write lock");

    println!("Inserting into cache...");

    cache_write.insert(url.clone(), SANCacheItem{
        cache_expire: 0,
        entry: root_output.clone()
    });

    println!("Inserted into cache");

    return Ok(Json(root_output));
}

#[get("/stats/cache")]
async fn get_stats(cache: &State<SANCache>) -> Json<CacheInfo> {
    Json(CacheInfo {
        num_entries: cache.data.read().await.len()
    })
}

#[launch]
fn rocket() -> _ {
    let allowed_origins =  AllowedOrigins::all();
    let cors = CorsOptions {
        allowed_origins,
        ..Default::default()
    }.to_cors().unwrap();

    let cache = SANCache {
        data: HashMap::new().into()
    };

    rocket::build()
        .manage(cache)
        .mount("/", routes![get_san, get_stats])
        .attach(cors)
}