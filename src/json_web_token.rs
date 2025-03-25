use tracing::{warn, error, debug};
use http::StatusCode;
use jsonwebtoken::{encode, decode, 
        Header, Validation, 
        EncodingKey, DecodingKey, 
        errors::Error};
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

type SessionStore = Arc<RwLock<HashMap<String, (String, usize)>>>;

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

static SESSION_STORE: Lazy<SessionStore> = Lazy::new(|| {
    Arc::new(RwLock::new(HashMap::new()))
}); 


fn _register_token_in_session(token: &str, user: &str, exp_time: usize) {
    // let clone_session = SESSION_STORE.clone();
    let mut session = SESSION_STORE.write().unwrap();

    // find session with the same user and remove it before inserting new one
    if let Some(key) = session.iter().find(|(_, (username, _))| username == user).map(|(key, _)| key.clone()) {
        session.remove(&key);
    }
    session.insert(token.to_string(), (user.to_string(), exp_time));

    debug!("Registered sessions: {}", session.keys().len());
}

pub fn create_jwt(user: &str, secret: &str, ttl_seconds: usize) -> Result<String, Error> {
    let exp_time = chrono::Utc::now().timestamp() as usize + ttl_seconds;
    let claims = Claims {
        sub: user.to_string(),
        exp: exp_time
    };
    let token = encode(&Header::default(), 
                    &claims, 
                &EncodingKey::from_secret(secret.as_ref()))?;

    _register_token_in_session(&token, user, exp_time);

    Ok(token)
}

pub fn verify_jwt(token: &str, secret: &str) -> Result<String, StatusCode> {

    let token_data = decode::<Claims>(
        token, 
        &DecodingKey::from_secret(secret.as_ref()), 
        &Validation::default())
        .map_err(|e| {
            error!("Error decoding token: {:?}", e);
            StatusCode::UNAUTHORIZED
        })?;
    let token_user = token_data.claims.sub.clone();
    let token_exp_time = token_data.claims.exp;
    let registered: bool;
    {  // block to release the lock
    // let clone_session = SESSION_STORE.clone();
    let mut session = SESSION_STORE.write().unwrap();
    let session_data = session.get(token);
    if session_data.is_none() {
        warn!("Token was not created and registered in the session");
        registered = false;
    } else {
        registered = true;
        let (user, exp_time) = session_data.unwrap();
        let cur_time = chrono::Utc::now().timestamp() as usize;
        if cur_time > *exp_time {
            error!("Token expired");
            session.remove(token);
            return Err(StatusCode::UNAUTHORIZED);
        }
        if token_user != *user {
            error!("Token user is different from the registered user");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    }
    // This for case when we re-started the app and the token is still valid.
    if !registered {
        _register_token_in_session(token, &token_user, token_exp_time);
    }
    
    Ok(token_user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    const TTL_SECONDS: usize = 3600;

    fn _cleanup_sessions() {
        // let clone_session = SESSION_STORE.clone();
        let mut session = SESSION_STORE.write().unwrap();
        session.clear();
    }

    #[test]
    #[serial]
    fn test_create_jwt() {
        let token = create_jwt("test", "secret", TTL_SECONDS).unwrap();
        println!("Token: {}", token);
        assert_eq!(token.len() > 0, true);
    }

    #[test]
    #[serial]
    fn test_verify_jwt() {
        let token = create_jwt("test", "secret", TTL_SECONDS).unwrap();
        let user = verify_jwt(&token, "secret").unwrap();
        assert_eq!(user, "test");
    }

    #[test]
    #[serial]
    fn test_verify_sessions_storage() {
        _cleanup_sessions();

        let token = create_jwt("test", "secret", TTL_SECONDS).unwrap();
        
        // let clone_session = SESSION_STORE.clone();
        let session = SESSION_STORE.read().unwrap();
        let exp_time = session.get(&token);
        assert_eq!(exp_time.is_some(), true);
    }

    #[test]
    #[serial]
    fn test_verify_sessions_storage_multiple_sessions() {

        _cleanup_sessions();

        let token = create_jwt("test", "secret", TTL_SECONDS).unwrap();
        println!("Token: {}", token);
        let another_token = create_jwt("anothertest", "secret", TTL_SECONDS).unwrap();
        println!("Another token: {}", another_token);
        
        // let clone_session = SESSION_STORE.clone();
        let session = SESSION_STORE.read().unwrap();
        let exp_time = session.get(&token);
        assert_eq!(exp_time.is_some(), true);

        let exp_time = session.get(&another_token);
        assert_eq!(exp_time.is_some(), true);

        assert!(token != another_token);
    }

    #[test]
    #[serial]
    fn test_verify_sessions_storage_one_session_per_user() {
        
        _cleanup_sessions();

        let token = create_jwt("bob", "secret", TTL_SECONDS).unwrap();
        println!("Token (bob): {}", token);
        let another_token = create_jwt("alice", "secret", TTL_SECONDS).unwrap();
        println!("Token (alice): {}", another_token);

        // let clone_session = SESSION_STORE.clone();
        {
        let session = SESSION_STORE.read().unwrap();
        println!("Sessions: {}", session.keys().len());
        assert!(session.keys().len() == 2);
        }
        // Need to sleep because it is generating the same JWT for the same user and 
        // we can not understand that it works correctly
        std::thread::sleep(std::time::Duration::from_secs(3));

        // used the same user, should remove the previous session and add new one
        let token_same_user = create_jwt("bob", "secret", TTL_SECONDS).unwrap();
        println!("Token (bob again): {}", token_same_user);
        
        let session = SESSION_STORE.read().unwrap();
        // Number of sessions should be the same
        assert!(session.keys().len() == 2);
    }

    #[test]
    #[serial]
    fn test_verify_expired_token() {
        // TTL = 1 second
        let token = create_jwt("test", "secret", 1).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let user = verify_jwt(&token, "secret");
        assert_eq!(user.is_err(), true);
        assert!(user.unwrap_err() == StatusCode::UNAUTHORIZED);
    }
}