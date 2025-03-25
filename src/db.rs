use async_trait::async_trait;
use tokio_postgres::{error::SqlState, types::ToSql, Client, Error, NoTls, Row};

use crate::types::{ProjectErrors, TransactionDetails};
use serde::de::DeserializeOwned;

static SCHEMA_HASH_DATA: &str = r#"
    CREATE TABLE IF NOT EXISTS hash_data (
            "id" SERIAL PRIMARY KEY,
            "transactionHash" TEXT NOT NULL UNIQUE,
            "transactionStatus" TEXT NOT NULL,
            "blockHash" TEXT NOT NULL,
            "blockNumber" INT NOT NULL,
            "from" TEXT NOT NULL,
            "to" TEXT,
            "contractAddress" TEXT,
            "logsCount" INT NOT NULL,
            "input" TEXT NOT NULL,
            "value" TEXT NOT NULL,
            "created_at" TIMESTAMP DEFAULT NOW()
        );
"#;
static SCHEMA_HASH_LOGS: &str = r#"
    CREATE TABLE IF NOT EXISTS hash_logs (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        hash_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (hash_id) REFERENCES hash_data (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
"#;

static QUERY_INSERT_TRANSACTION_DETAILS_SAFELY: &str = r#"
WITH user_data AS (
   SELECT id AS user_id FROM users WHERE username = $11),
existing_hash AS (
    SELECT id FROM hash_data WHERE "transactionHash" = $1
),
inserted_hash AS (
    INSERT INTO hash_data ("transactionHash", "transactionStatus", "blockHash", "blockNumber", 
                        "from", "to", "contractAddress", "logsCount", "input", "value")
    SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
    WHERE NOT EXISTS (SELECT 1 FROM existing_hash)
    RETURNING id AS hash_id)
INSERT INTO hash_logs (user_id, hash_id)
    SELECT user_data.user_id, inserted_hash.hash_id
        FROM user_data, inserted_hash
    UNION ALL
    SELECT user_data.user_id, existing_hash.id
        FROM user_data, existing_hash;
"#;

static QUERY_INSERT_TRANSACTION_DETAILS_NO_LOGS: &str = r#"
    INSERT INTO hash_data ("transactionHash", "transactionStatus", "blockHash", "blockNumber", 
                        "from", "to", "contractAddress", "logsCount", "input", "value")
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
    "#;


struct User;
impl User {
    fn id_from_row(row: &Row) -> i32 {
        row.get("id")
    }
}

#[async_trait]
pub trait Db: Send + Sync {
    async fn connect(db_connection_url: &str) -> Result<Self, Error>
    where
        Self: Sized;
    async fn get_user_id(&self, username: &str, password: &str) -> Result<i32, ProjectErrors>;
    async fn get_transaction_details_list(&self, username: &str) -> Result<Vec<TransactionDetails>, ProjectErrors>;
    async fn get_transaction_details(&self, transaction_hash: &str, username: &str) -> Result<TransactionDetails, ProjectErrors>;
    async fn store_transaction_details(&self, details: &TransactionDetails, username: &str) -> Result<(), Error>;
}

trait PrivateDb {
    async fn sql_query<T>(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<T>, Error>
        where
        T: DeserializeOwned + From<Row>,;
    async fn create_table_if_not_exists(&self, query: &str) -> Result<(), Error>;
}

pub struct PostgresDb {
    #[cfg(not(test))]
    client: Client,
    #[cfg(test)]
    pub client: Client, 
}


#[async_trait]
impl Db for PostgresDb {
    async fn connect(db_connection_url: &str) -> Result<Self, Error> {
        let (client, connection) = tokio_postgres::connect(
            db_connection_url,
            NoTls,
        )
        .await?;

        // TODO convert to error handling using 'thiserror' crate if you will have a time
        tokio::spawn(connection); // Fire and forget
        Ok(PostgresDb { client })
    }

    async fn get_user_id(&self, username: &str, password: &str) -> Result<i32, ProjectErrors> {
        let query = r#"
            SELECT id FROM users WHERE username = $1 AND password=crypt($2, password)
        "#;
        let row = self.client.query_opt(query, &[&username, &password]).await?;
        match row {
            Some(row) => {
                let user_id = User::id_from_row(&row);
                Ok(user_id)
            },
            None   => return Err(ProjectErrors::UserNotFound)
        }
    }

    // Pass here a uesrname and get the transactions associated with that user
    // if username is empty, return all transactions
    async fn get_transaction_details_list(&self, username: &str) -> Result<Vec<TransactionDetails>, ProjectErrors> {
        let query;
        let parameters: Vec<&(dyn ToSql + Sync)>;
        if username.is_empty() {
            query = r#"
            SELECT * FROM hash_data
            "#;
            parameters = vec![];
        } else {
            query = r#"
            SELECT * FROM hash_data WHERE id IN (
                SELECT hash_id FROM hash_logs WHERE user_id = (
                    SELECT id FROM users WHERE username = $1
                )
            )
            "#;
            parameters = vec![&username];
        }
        let res = self.sql_query::<TransactionDetails>(query, &parameters).await;
        if res.is_err() {
            return Err(ProjectErrors::DbError(res.err().unwrap()));
        };
        let details = res.unwrap();
        if details.len() == 0 {
            return Err(ProjectErrors::NoTransactionsFound);
        }
        Ok(details)
    }

    async fn get_transaction_details(&self, transaction_hash: &str, username: &str) -> Result<TransactionDetails, ProjectErrors> {
        let query;
        let params: Vec<&(dyn ToSql + Sync)>;
        if username.is_empty() {
            query = r#"
            SELECT * FROM hash_data WHERE "transactionHash" = $1
            "#;
            params = vec![&transaction_hash];
        } else {
            query = r#"
            SELECT * FROM hash_data WHERE id IN (
                SELECT hash_id FROM hash_logs WHERE user_id = (
                    SELECT id FROM users WHERE username = $1
                ) AND hash_id = (
                    SELECT id FROM hash_data WHERE "transactionHash" = $2
                )
            )
            "#;
            params = vec![&username, &transaction_hash];
        }
        let res = self.sql_query::<TransactionDetails>(query, &params).await;
        if res.is_err() {
            return Err(ProjectErrors::DbError(res.err().unwrap()));
        };
        let details = res.unwrap();
        if details.len() == 0 {
            return Err(ProjectErrors::HashNotFound);
        }
        Ok(details.get(0).unwrap().clone())
    }

    async fn store_transaction_details(&self, details: &TransactionDetails, username: &str) -> Result<(), Error> {
        let query;        
        let mut params = details.to_list_of_params_db();

        if username.is_empty() {
            query = QUERY_INSERT_TRANSACTION_DETAILS_NO_LOGS;
        } else {
            query = QUERY_INSERT_TRANSACTION_DETAILS_SAFELY;
            params.push(&username as &(dyn ToSql + Sync));
        }
        tracing::debug!("Params: {:?}", params);
        // let params_ref = params.iter().map(|x| x as &(dyn ToSql + Sync)).collect::<Vec<&(dyn ToSql + Sync)>>();
        match self.client.execute(query, &params).await {
            Ok(_) => {
                println!("Query executed successfully.");
                return Ok(())
            },
            Err(e) => {
                if let Some(db_error) = e.as_db_error() {
                    if db_error.code() == &SqlState::UNDEFINED_TABLE {
                        println!("Table does not exist. Create it. Error: {}", e);

                        match self.create_table_if_not_exists(SCHEMA_HASH_DATA).await {
                            Ok(_) => {},
                            Err(e) => {
                                println!("Error creating table: {}", e);
                                return Err(e);
                            }
                        }
                        match self.create_table_if_not_exists(SCHEMA_HASH_LOGS).await {
                            Ok(_) => {},
                            Err(e) => {
                                println!("Error creating table: {}", e);
                                return Err(e);
                            }
                        }
                        println!(">>> Tables created. Retry query.");

                        match self.client.execute(query, &params).await {
                            Ok(_) => {
                                println!("Query executed successfully.");
                                return Ok(())
                            },
                            Err(e) => {
                                println!("Error executing query: {}", e);
                                return Err(e);
                            }
                        }
                    }
                }
                println!("Other SQL error: {}", e);
                return Err(e);
            }
        }
    }
}

impl PrivateDb for PostgresDb {
    // let user_id = 1; let username = "john_doe";
    // sql_query(&client, "SELECT * FROM users WHERE id = $1 AND username = $2", &[&user_id, &username]).await?;
    async fn sql_query<T>(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<T>, Error>
    where
    T: DeserializeOwned + From<Row>, {
        match self.client.query(query, params).await {
            Ok(rows) => {
                let results = rows.into_iter().map(T::from).collect();
                Ok(results)            
            },
            Err(e) => {
                if let Some(db_error) = e.as_db_error() {
                    if db_error.code() == &SqlState::UNDEFINED_TABLE {
                        println!("Table does not exist. Create it. Error: {}", e);

                        match self.create_table_if_not_exists(SCHEMA_HASH_DATA).await {
                            Ok(_) => {},
                            Err(e) => {
                                println!("Error creating table: {}", e);
                                return Err(e);
                            }
                        }
                        match self.create_table_if_not_exists(SCHEMA_HASH_LOGS).await {
                            Ok(_) => {},
                            Err(e) => {
                                println!("Error creating table: {}", e);
                                return Err(e);
                            }
                        }
                        println!(">>> Tables created. Retry query.");

                        match self.client.query(query, params).await {
                            Ok(rows) => {
                                println!("Query executed successfully.");
                                let results = rows.into_iter().map(T::from).collect();
                                return Ok(results);
                            },
                            Err(e) => {
                                println!("Error executing query: {}", e);
                                return Err(e);
                            }
                        }
                    }
                }
                println!("Other SQL error: {}", e);
                return Err(e);
            }
        }
    }
    async fn create_table_if_not_exists(&self, query: &str) -> Result<(), Error> {
        self.client.execute(query, &[]).await?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {

    use super::*;
    use once_cell::sync::Lazy;
    use serial_test::serial;
    use tracing_subscriber;
    use tracing::Level;
    use tracing_log::LogTracer;
    
    const CONNECT_URL: &str = "postgresql://testuser:testpass@localhost:5433/testdb";

    // Ensures logger is only initialized once for all tests
    static INIT_LOGGER: Lazy<()> = Lazy::new(|| {
        if LogTracer::init().is_err() {
            eprintln!("LogTracer is already initialized.");
        }
        if tracing_subscriber::fmt().with_max_level(Level::DEBUG).try_init().is_err() {
            eprintln!("Tracing subscriber is already initialized.");
        }
    });
    
    /// Call this function at the beginning of every test
    fn init_test_logger() {
        Lazy::force(&INIT_LOGGER);
    }

    #[tokio::test]
    #[serial]
    async fn test_connect() {
        init_test_logger();

        let db = PostgresDb::connect(CONNECT_URL).await;
        assert_eq!(db.is_ok(), true);
    }

    // implement From<Row> for TransactionDetails
    #[tokio::test]
    #[serial]
    async fn test_sql_query() {
        init_test_logger();

        let db = PostgresDb::connect(CONNECT_URL).await.unwrap();
        let res = db.sql_query::<TransactionDetails>("SELECT * FROM hash_data", &[]).await;
        assert_eq!(res.is_ok(), true);
    }

    #[tokio::test]
    #[serial]
    async fn test_create_table_if_not_exists() {
        init_test_logger();

        let db = PostgresDb::connect(CONNECT_URL).await.unwrap();
        let res = db.create_table_if_not_exists(SCHEMA_HASH_DATA).await;
        assert_eq!(res.is_ok(), true);
    }

    #[tokio::test]
    #[serial]
    async fn test_get_transaction_details_list() {
        init_test_logger();

        let db = PostgresDb::connect(CONNECT_URL).await.unwrap();
        let res = db.get_transaction_details_list("bob").await;
        assert_eq!(res.is_err(), true);
    }

    #[tokio::test]
    #[serial]
    async fn test_store_transaction_details() {

        init_test_logger();

        let db = PostgresDb::connect(CONNECT_URL).await.unwrap();
        let details = TransactionDetails::new();
        let res = db.store_transaction_details(&details, "alice").await;
        assert_eq!(res.is_ok(), true);
    }

}
