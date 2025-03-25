pub mod types;
pub mod eth_fetcher;
pub mod db;
pub mod json_web_token;

use std::env;
use db::Db;
use once_cell::sync::Lazy;
use rlp::Rlp;

use tracing::{debug, error, info, warn};
use tracing_log::LogTracer;
use tracing_subscriber;

use axum::{
    routing::get,
    routing::post,
    http::StatusCode,
    http::header::HeaderMap,
    Router,
    Json,
    extract::Query,
    extract::Path,
    extract::Request,
};

use serde::{Deserialize, Serialize};

use eth_fetcher::{EthFetcher, EthTransactionsFetcher};
use types::{ProjectErrors, TransactionDetailsList};

// block of environment variables to be used
static API_PORT: Lazy<String> = Lazy::new(|| {
    env::var("API_PORT").unwrap_or("3000".to_string())
});
static ETH_NODE_URL: Lazy<String> = Lazy::new(|| {
    env::var("ETH_NODE_URL").unwrap_or("https://mainnet.infura.io/v3/28d8b996e9174e82a7d049f4198deed1".to_string())
});
static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    env::var("JWT_SECRET").unwrap_or("1234567890".to_string())
});
#[cfg(not(test))]
static DB_CONNECTION_URL: Lazy<String> = Lazy::new(|| {
    env::var("DB_CONNECTION_URL").unwrap_or("postgresql://postgres:postgres@localhost:5432/postgres".to_string())
});
#[cfg(test)]
static DB_CONNECTION_URL: Lazy<String> = Lazy::new(|| {
    env::var("DB_CONNECTION_URL").unwrap_or("postgresql://testuser:testpass@localhost:5433/testdb".to_string())
});



// for unit testing I'll be able to set it like DB = db::MockDb
type DB = db::PostgresDb;

const TTL_SECONDS: usize = 3600; // 1 hour

#[tokio::main]
async fn main() {
    // initialize tracing
    if LogTracer::init().is_err() {
        eprintln!("LogTracer is already initialized.");
    }
    if tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).try_init().is_err() {
        eprintln!("Tracing subscriber is already initialized.");
    }

    info!("Starting server...");

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", API_PORT.as_str())).await.unwrap();
    axum::serve(listener, app()).await.unwrap();
}

fn app() -> Router {
    Router::new()
    .route("/lime/eth", get(handle_eth_transactions))
    .route("/lime/eth/{:rlphex}", get(handle_eth_rlphex))
    .route("/lime/all", get(handle_get_all))
    .route("/lime/my", get(handle_my_transactions))
    .route("/lime/authenticate", post(handle_authenticate))
}

#[derive(Debug, Deserialize, Serialize)]
struct Authenticated {
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct LoginPassword {
    username: String,
    password: String,
}


async fn handle_authenticate(Json(param): Json<LoginPassword>) -> (StatusCode, Json<Authenticated>) {
    // The database should have a `users` table containing different users' credentials.
    // The server should handle a POST request on an endpoint named `/lime/authenticate`.
    // The request body should be a JSON object containing the username and password.
    // Upon sending correct `username` and `password` (list of usernames and passwords below), 
    // the server should respond with a JWT token.
    // The response format should be
    // {
    //   "token": string // The JWT token for the user
    // } 
    debug!("handle_authenticate");

    let auth = param;
    let dbobj = DB::connect(
                DB_CONNECTION_URL.as_str()).await;
    if dbobj.is_err() {
        error!("Error connecting to the database: {:?}", dbobj.err().unwrap());
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Authenticated { token: "".to_string() }));
    }
    let dbobj = dbobj.unwrap();
    let user_id = dbobj.get_user_id(&auth.username, &auth.password).await;
    if user_id.is_err() {
        return (StatusCode::UNAUTHORIZED, Json(Authenticated { token: "".to_string() }));
    }
    // create JWT token, pass user name, not user_id
    let jwt = json_web_token::create_jwt(
                auth.username.as_str(), 
                JWT_SECRET.as_str(), 
                TTL_SECONDS);
    if jwt.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Authenticated { token: "".to_string() }));
    }

    let ret_jwt = Authenticated {
        token: jwt.unwrap(),
    };
    (StatusCode::OK, Json(ret_jwt))
}

/// TODO. This function might be moved to facade layer.
/// Check JWT token
fn _check_jwt(auth_token: &str) -> Result<String, StatusCode> {
    // check JWT token
    let jwt_data = json_web_token::verify_jwt(auth_token, JWT_SECRET.as_str());
    if jwt_data.is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(jwt_data.unwrap())
}

/// TODO. This function might be moved to facade layer.
/// get transaction details by hash from the database
/// if some transaction not fouond in the database, fetch from the network.
/// If user name is not empty - store the requested transaction details in the database.
async fn _get_transaction_details(dbobj: &DB, hashes_lst: &Vec<&str>, user: &str) -> (StatusCode, String){    
    debug!("_get_transaction_details");

    // let mut details_list:Vec<types::TransactionDetails> = Vec::new();
    let mut details_list = types::TransactionDetailsList::new();

    let mut fetcher = EthTransactionsFetcher::new();
    fetcher.set_url(ETH_NODE_URL.as_str());

    // get transaction details by hash one by one
    // if some transaction not found in the database, fetch from the network, store in the database
    for item in hashes_lst {
        match dbobj.get_transaction_details(item, user).await {
            Ok(details) => details_list.push(details),
            Err(e) => {
                if e.to_string().contains("Hash not found in Db") {
                    let details = fetcher.fetch_transaction_details(item).await;
                    if details.is_err() {
                        let details = details.err().unwrap();
                        error!("Error for hash: {} {:?}", item, details);
                        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{:?}", details));
                    } else {
                        let details = details.unwrap();
                        details_list.push(details.clone());
                        
                        let res = dbobj.store_transaction_details(&details, user).await;
                        if res.is_err() {
                            error!("Error inserting transaction details: hash: {} {:?}", item, res.as_ref().err().unwrap());
                            return (StatusCode::INTERNAL_SERVER_ERROR, res.err().unwrap().to_string());
                        }
                    }
                } else {
                    error!("Error getting transaction details: hash: {} {:?}", item, e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
                }
            }
        }
    }
    (StatusCode::OK, serde_json::to_string(&details_list).unwrap())
}

fn _rlp_decoding(rlphex: &str) -> Result<Vec<String>, ProjectErrors> {

    let decoded = hex::decode(rlphex)?;
    let rlp = Rlp::new(&decoded);
    let lst: Vec<String> = rlp.as_list()?;
    // let lst = lst.iter().map(|x| x.as_str()).collect::<Vec<&str>>();
    info!("Transaction hashes(RLP): {:?}", lst);
    return Ok(lst);
}

/// The server handles a GET request at an endpoint named `/lime/eth` with query 
/// parameters `transactionHashes`. The AUTH_TOKEN header is optional for this endpoint.
async fn handle_eth_transactions(
    Query(params): Query<Vec<(String, String)>>,
    request: Request,
) -> (StatusCode, String) {
    debug!("handle_eth_transactions");

    let all_match = params.iter().all(|(key, _value)| key == "transactionHashes");
    if !all_match {
        error!("The query parameter must have the name transactionHashes: {:?}", params);
        return (StatusCode::BAD_REQUEST, "Invalid query parameters".to_string());
    }
    let user: String;
    let headers: &HeaderMap = request.headers();
    // Get the value of the header AUTH_TOKEN
    let auth_token = headers.get("AUTH_TOKEN");
    if auth_token.is_none() {
        warn!("No AUTH_TOKEN header");
        user = "".to_string();
    } else {
        let res = _check_jwt(auth_token.unwrap().to_str().unwrap());
        if res.is_err() {
            return (res.err().unwrap(), "Invalid JWT token".to_string());
        }
        user = res.unwrap();
    }

    // get list of transaction hashes from the query parameters
    let lst = params.iter().map(|(_key, value)| value).collect::<Vec<&String>>();
    let lst = lst.iter().map(|x| x.as_str()).collect::<Vec<&str>>();
    info!("Transaction hashes: {:?}", lst);

    let dbobj = DB::connect(
        DB_CONNECTION_URL.as_str()).await;
    if dbobj.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, dbobj.err().unwrap().to_string());
    }
    let dbobj = dbobj.unwrap();

    _get_transaction_details(&dbobj, &lst, &user).await
}

/// It has a single parameter `rlphex` - a hexadecimal representation of RLP encoded 
/// list of transaction hashes. The AUTH_TOKEN header is optional for this endpoint.
/// This is an upgrade over the first endpoint with the only difference being the way 
/// in which the transaction hashes are gathered - decode the RLP to list of hashes.
async fn handle_eth_rlphex(Path(rlphex): Path<String>, request: Request) -> (StatusCode, String) {
    debug!("handle_eth_rlphex");

    let user: String;
    let headers: &HeaderMap = request.headers();
    // Get the value of the header AUTH_TOKEN
    let auth_token = headers.get("AUTH_TOKEN");
    if auth_token.is_none() {
        warn!("No AUTH_TOKEN header");
        user = "".to_string();
    } else {
        let res = _check_jwt(auth_token.unwrap().to_str().unwrap());
        if res.is_err() {
            return (res.err().unwrap(), "Invalid JWT token".to_string());
        }
        user = res.unwrap();
    }

    let lst = _rlp_decoding(rlphex.as_str());
    if lst.is_err() {
        return (StatusCode::BAD_REQUEST, lst.err().unwrap().to_string());
    }
    let lst = lst.unwrap();

    let dbobj = DB::connect(
        DB_CONNECTION_URL.as_str()).await;
    if dbobj.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, dbobj.err().unwrap().to_string());
    }
    let dbobj = dbobj.unwrap();
    let lst = lst.iter().map(|x| x.as_str()).collect::<Vec<&str>>();
    _get_transaction_details(&dbobj, &lst, &user).await
}

/// The server handles a GET request at an endpoint named `/lime/my`. 
/// It has no required parameters and returns a list of all transactions 
/// saved in the database that are associated with the user that is currently 
/// authenticated. The response format is the same as `/lime/eth/:rlphex`.
/// It should has a single parameter in the header `AUTH_TOKEN` - the JWT token of the user.
async fn handle_my_transactions(request: Request) -> (StatusCode, String) {
    debug!("handle_my_transactions");

    let headers: &HeaderMap = request.headers();
    // Get the value of the header AUTH_TOKEN
    let auth_token = headers.get("AUTH_TOKEN");
    if auth_token.is_none() {
        error!("No AUTH_TOKEN header");
        return (StatusCode::UNAUTHORIZED, "No AUTH_TOKEN header".to_string());
    }
    let res = _check_jwt(auth_token.unwrap().to_str().unwrap());
    if res.is_err() {
        return (res.err().unwrap(), "Invalid JWT token".to_string());
    }
    let user = res.unwrap();

    let dbobj = DB::connect(
        DB_CONNECTION_URL.as_str()).await;
    if dbobj.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, dbobj.err().unwrap().to_string());
    }
    let dbobj = dbobj.unwrap();
    let lst = dbobj.get_transaction_details_list(&user).await;
    if lst.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, lst.err().unwrap().to_string());
    }
    let mut details_list = TransactionDetailsList::new();
    for item in lst.unwrap() {
        details_list.push(item);
    }
    debug!("My Transactions details list: {:?}", details_list);
    (StatusCode::OK, serde_json::to_string(&details_list).unwrap())
}

async fn handle_get_all() -> (StatusCode, String) {
    // The server should handle a GET request at an endpoint named `/lime/all` . 
    // It should have no required parameters and return a list of all transactions 
    // saved in the database. The response format should be the same as `/lime/eth/:rlphex`.
    debug!("handle_get_all");
    let dbobj = DB::connect(
        DB_CONNECTION_URL.as_str()).await;
    if dbobj.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, dbobj.err().unwrap().to_string());
    }
    let dbobj = dbobj.unwrap();
    let lst = dbobj.get_transaction_details_list("").await;
    if lst.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, lst.err().unwrap().to_string());
    }
    let mut details_list = TransactionDetailsList::new();
    for item in lst.unwrap() {
        details_list.push(item);
    }
    debug!("Details list: {:?}", details_list);
    (StatusCode::OK, serde_json::to_string(&details_list).unwrap())
}


#[cfg(test)]
mod tests {
    use super::*;
    use urlencoding::encode;
    use http::{Request, Response, StatusCode};
    use axum::body::Body;
    use tower::ServiceExt; // For `oneshot` testing of axum routes.

    use rlp::RlpStream;
    use serial_test::serial;

    // Ensures logger is only initialized once for all tests
    static INIT_LOGGER: Lazy<()> = Lazy::new(|| {
        if LogTracer::init().is_err() {
            eprintln!("LogTracer is already initialized.");
        }
        if tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).try_init().is_err() {
            eprintln!("Tracing subscriber is already initialized.");
        }
    });
    
    /// Call this function at the beginning of every test
    fn init_test_logger() {
        Lazy::force(&INIT_LOGGER);
    }

    fn _prepare_jwt(user: &str) -> String {
        let jwt = json_web_token::create_jwt(user, JWT_SECRET.as_str(), TTL_SECONDS);
        jwt.unwrap()
    }

    async fn _prepare_hashes_in_db(lst: Vec<&str>, jwtoken: &str) {
        debug!("_prepare_hashes_in_db");
        init_test_logger();
        // Set up the Axum app
        let app = app();

        let formatted_query = lst.iter()
                                .map(|hash| format!("transactionHashes={}", encode(hash)))
                                .collect::<Vec<String>>()
                                .join("&");
        
        let mut request = Request::builder()
            .uri(format!("/lime/eth?{}", formatted_query))
            .body(axum::body::Body::empty())
            .unwrap();

        if jwtoken.len() > 0 {
            let headers = request.headers_mut();
            headers.insert("AUTH_TOKEN", jwtoken.parse().unwrap());
        }

        let response: Response<Body> = app.oneshot(request).await.unwrap();
        info!("{:?}", response);
    }

    async fn _cleanup_db() {
        debug!("_cleanup_db");
        let query = r#"
        DO $$
        BEGIN
            IF EXISTS (
                SELECT FROM pg_catalog.pg_tables 
                WHERE schemaname = 'public' AND tablename = 'hash_data'
            ) THEN
                EXECUTE 'DELETE FROM hash_data';
            END IF;
        END $$;
        "#;

        let db = DB::connect(DB_CONNECTION_URL.as_str()).await.unwrap();
        let res = db.client.batch_execute(query).await.unwrap();
        info!("Cleanup: {:?}", res);
    }

    async fn _check_all() -> TransactionDetailsList {
        let request = Request::builder()
            .uri("/lime/all")
            .body(axum::body::Body::empty())
            .unwrap();
        debug!("{}", DB_CONNECTION_URL.as_str());

        let app = app();
        let response: Response<Body> = app.oneshot(request).await.unwrap();
        info!("{:?}", response);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();
        debug!("Body: {}", body_str);

        serde_json::from_str::<TransactionDetailsList>(&body_str).unwrap()
    }

    async fn _check_my(jwtoken: &str) -> TransactionDetailsList {
        let mut request = Request::builder()
            .uri("/lime/my")
            .body(axum::body::Body::empty())
            .unwrap();
        request.headers_mut().insert("AUTH_TOKEN", jwtoken.parse().unwrap());

        let app = app();
        let response: Response<Body> = app.oneshot(request).await.unwrap();
        info!("{:?}", response);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();
        debug!("Body: {}", body_str);

        serde_json::from_str::<TransactionDetailsList>(&body_str).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial]
    async fn test_handle_rlphex_with_token() {
        init_test_logger();

        _cleanup_db().await;

        let rlphex = "f8ccb842307865356664616430336234323239383232623139303934626566633431386466363035356231303237323337643438393137656338336337613062343237333237b842307830626239363737326536326432376665636130643339323563383365306462653932396138633037323831343335623039663133653436663439633233636133b842307839623832356265616637653165373932333062633965306637316134633065393835326436343566656636383865326664633331303462343862323738333730";

        // Set up the Axum app
        let app = app();
    
        // Generate JWT token for user alice to use it in the request
        let token = _prepare_jwt("alice");

        let mut request = Request::builder()
            .uri("/lime/eth/".to_string() + rlphex)
            .body(axum::body::Body::empty())
            .unwrap();
        request.headers_mut().insert("AUTH_TOKEN", token.parse().unwrap());

        let response: Response<Body> = app.oneshot(request).await.unwrap();
        info!("{:?}", response);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();

        let result = serde_json::from_str::<TransactionDetailsList>(&body_str).unwrap();
        assert_eq!(result.transactions.len(), 3);
        assert_eq!(result.transactions[0].transaction_hash, "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327");
        assert_eq!(result.transactions[1].transaction_hash, "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3");
        assert_eq!(result.transactions[2].transaction_hash, "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370");

        let all = _check_all().await;
        assert_eq!(all.transactions.len(), 3);
        assert_eq!(all.transactions[0].transaction_hash, "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327");
        assert_eq!(all.transactions[1].transaction_hash, "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3");
        assert_eq!(all.transactions[2].transaction_hash, "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370");

        let my = _check_my(&token).await;
        assert_eq!(my.transactions.len(), 3);
        assert_eq!(my.transactions[0].transaction_hash, "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327");
        assert_eq!(my.transactions[1].transaction_hash, "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3");
        assert_eq!(my.transactions[2].transaction_hash, "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370");
    }


    #[tokio::test(flavor = "current_thread")]
    #[serial]
    async fn test_handle_rlphex_no_token() {
        // JWT Token is optional, so these items will be added
        // without token and will be visible for /lime/all endpoint
        init_test_logger();

        _cleanup_db().await;

        let rlphex = "f8ccb842307865356664616430336234323239383232623139303934626566633431386466363035356231303237323337643438393137656338336337613062343237333237b842307830626239363737326536326432376665636130643339323563383365306462653932396138633037323831343335623039663133653436663439633233636133b842307839623832356265616637653165373932333062633965306637316134633065393835326436343566656636383865326664633331303462343862323738333730";

        // Set up the Axum app
        let app = app();
    
        let request = Request::builder()
            .uri("/lime/eth/".to_string() + rlphex)
            .body(axum::body::Body::empty())
            .unwrap();

        let response: Response<Body> = app.oneshot(request).await.unwrap();
        info!("{:?}", response);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();

        let result = serde_json::from_str::<TransactionDetailsList>(&body_str).unwrap();
        assert_eq!(result.transactions.len(), 3);
        assert_eq!(result.transactions[0].transaction_hash, "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327");
        assert_eq!(result.transactions[1].transaction_hash, "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3");
        assert_eq!(result.transactions[2].transaction_hash, "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370");

        let all = _check_all().await;
        assert_eq!(all.transactions.len(), 3);
        assert_eq!(all.transactions[0].transaction_hash, "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327");
        assert_eq!(all.transactions[1].transaction_hash, "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3");
        assert_eq!(all.transactions[2].transaction_hash, "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370");
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial]
    async fn test_handle_get_my() {
        init_test_logger();

        _cleanup_db().await;

        let lst = vec![
            "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327",
        ];
        let token = _prepare_jwt("alice");
        _prepare_hashes_in_db(lst, &token).await;
        // Set up the Axum app
        let app = app();
    
        let mut request = Request::builder()
            .uri("/lime/my")
            .body(axum::body::Body::empty())
            .unwrap();
        request.headers_mut().insert("AUTH_TOKEN", token.parse().unwrap());

        debug!("DB_CONNECTION_URL: {}", DB_CONNECTION_URL.as_str());

        let response: Response<Body> = app.oneshot(request).await.unwrap();
        info!("{:?}", response);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();

        let result = serde_json::from_str::<TransactionDetailsList>(&body_str).unwrap();
        assert_eq!(result.transactions.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial]
    async fn test_handle_get_my_no_token() {
        // JWT Token in required header parameter for this endpoint
        init_test_logger();

        _cleanup_db().await;

        let lst = vec![
            "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327",
        ];
        // token is empty string
        _prepare_hashes_in_db(lst, "").await;
        // Set up the Axum app
        let app = app();
    
        let request = Request::builder()
            .uri("/lime/my")
            .body(axum::body::Body::empty())
            .unwrap();

        debug!("DB_CONNECTION_URL: {}", DB_CONNECTION_URL.as_str());

        let response: Response<Body> = app.oneshot(request).await.unwrap();
        info!("{:?}", response);

        // Without required JWT token the server should respond with status code 401
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial]
    async fn test_handle_get_all() {
        init_test_logger();

        _cleanup_db().await;

        let lst = vec![
            "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327",
            "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3",
        ];
        _prepare_hashes_in_db(lst, "").await;
        // Set up the Axum app
        let app = app();
    
        let request = Request::builder()
            .uri("/lime/all")
            .body(axum::body::Body::empty())
            .unwrap();
        debug!("{}", DB_CONNECTION_URL.as_str());

        let response: Response<Body> = app.oneshot(request).await.unwrap();
        info!("{:?}", response);

        // Assert the status code and response body
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();
        debug!("Body: {}", body_str);

        let result = serde_json::from_str::<TransactionDetailsList>(&body_str).unwrap();
        assert_eq!(result.transactions.len(), 2);
    }

    #[test]
    #[serial]
    fn test_rlp_encoding() {

        let lst = vec![
            "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327",
            "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3",
            "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370"
        ];

        // encode list of strings
        let mut stream = RlpStream::new_list(lst.len());
        for item in lst {
            stream.append(&item);
        }
        let encoded = stream.out().to_vec();
        let rlphex = hex::encode(&encoded);
        println!("RLP hex: {:?}", rlphex);
        assert_eq!(rlphex, "f8ccb842307865356664616430336234323239383232623139303934626566633431386466363035356231303237323337643438393137656338336337613062343237333237b842307830626239363737326536326432376665636130643339323563383365306462653932396138633037323831343335623039663133653436663439633233636133b842307839623832356265616637653165373932333062633965306637316134633065393835326436343566656636383865326664633331303462343862323738333730");
    }

    #[test]
    #[serial]
    fn test_rlp_decoding() {
        // decode RLP buffer to list of strings encoded before
        let rlphex = "f8ccb842307865356664616430336234323239383232623139303934626566633431386466363035356231303237323337643438393137656338336337613062343237333237b842307830626239363737326536326432376665636130643339323563383365306462653932396138633037323831343335623039663133653436663439633233636133b842307839623832356265616637653165373932333062633965306637316134633065393835326436343566656636383865326664633331303462343862323738333730";
        let res = _rlp_decoding(rlphex);
        assert_eq!(res.is_ok(), true);

        let res = res.unwrap();
        assert_eq!(res.len(), 3);
        assert_eq!(res[0], "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327");
        assert_eq!(res[1], "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3");
        assert_eq!(res[2], "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370");
    }
}
