#[macro_use]
extern crate rocket;
use std::io::Write;
use openssl::ssl::{SslConnector, SslMethod};
use rocket::serde::{json::Json, Serialize};
use rocket_cors::{AllowedOrigins, CorsOptions};


#[derive(Serialize)]
struct StatusMessage {
    message: String
}


#[derive(Serialize)]
struct SANEntry {
    host: String,
    success: bool,
    children: Vec<SANEntry>
}

fn openssl_san_recursive(url: &str, parent_node: &mut SANEntry, found_vec: &mut Vec<String>, connector: &SslConnector) {


    // if found_vec.contains(&url.to_string()) {
    //     return;
    // }

    // check if its a regular host url, not a wildcard
    if url.contains("*") {
        return;
    }
    
    println!("{} Scanning right now ", url);
    
    let stream = std::net::TcpStream::connect((url, 443));

    if stream.is_err() {
        parent_node.success = false;
        return;
    }

    let stream = connector.connect(url, stream.unwrap());

    if stream.is_err() {
        parent_node.success = false;
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
    
            let mut child = SANEntry {
                host: san.to_string(),
                success: true,
                children: vec![]
            };
    
            found_vec.push(ent.dnsname().unwrap().to_string());
            openssl_san_recursive(ent.dnsname().unwrap(), &mut child, found_vec, &connector);

            parent_node.children.push(child);
        }


    }

    
}

#[get("/query/<url>")]
async fn get_san(url: &str) -> Result<Json<SANEntry>, String> {
    // url decode the parameter
    let url = urlencoding::decode(url).unwrap().into_owned();
    
    let mut root_output = SANEntry {
        host: url.to_string(),
        success: true,
        children: vec![]
    };

    let mut found_hosts = vec![];
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    openssl_san_recursive(&url, &mut root_output, &mut found_hosts, &connector);

    return Ok(Json(root_output));
}


#[launch]
fn rocket() -> _ {
    let allowed_origins =  AllowedOrigins::all();
    let cors = CorsOptions {
        allowed_origins,
        ..Default::default()
    }.to_cors().unwrap();

    rocket::build()
        .mount("/", routes![get_san])
        .attach(cors)
}