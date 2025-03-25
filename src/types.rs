use serde::{Deserialize, Serialize};
use tokio_postgres::{Row, types::ToSql};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProjectErrors {
    #[error("Database error: {0}")]
    DbError(#[from] tokio_postgres::Error),
    #[error("User not found")]
    UserNotFound,
    #[error("Hash not found in Db")]
    HashNotFound,
    #[error("No transactions found")]
    NoTransactionsFound,
    #[error("FromHex error: {0}")]
    FromHexError(#[from] hex::FromHexError),
    #[error("RLP ddecoder error: {0}")]
    RlpDecoderError(#[from] rlp::DecoderError),
}

#[derive(Debug)]
pub enum FetcherError {
    TransactionHashNetworkError(String),
    TransactionHashParsingError(String),
    TransactionReceiptNetworkError(String),
    TransactionReceiptParsingError(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionDetails {
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "transactionStatus")]
    pub transaction_status: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: i32,
    pub from: String,
    pub to: Option<String>,         // or null
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<String>,  // or null
    #[serde(rename = "logsCount")]
    pub logs_count: i32,
    pub input: String,
    pub value: String 
}
impl TransactionDetails {
    pub fn new() -> Self {
        TransactionDetails {
            transaction_hash: String::new(),
            transaction_status: String::new(),
            block_hash: String::new(),
            block_number: 0,
            from: String::new(),
            to: None,
            contract_address: None,
            logs_count: 0,
            input: String::new(),
            value: String::new()
        }
    }
    pub fn to_list_of_params_db(&self) -> Vec<&(dyn ToSql + Sync)> {
        vec![
            &self.transaction_hash,
            &self.transaction_status,
            &self.block_hash,
            &self.block_number,
            &self.from,
            &self.to,
            &self.contract_address,
            &self.logs_count,
            &self.input,
            &self.value
        ]
    }
}

impl From<tokio_postgres::Row> for TransactionDetails {
    fn from(row: Row) -> Self {
        TransactionDetails {
            transaction_hash: row.get("transactionHash"),
            transaction_status: row.get("transactionStatus"),
            block_hash: row.get("blockHash"),
            block_number: row.get("blockNumber"),
            from: row.get("from"),
            to: row.get("to"),
            contract_address: row.get("contractAddress"),
            logs_count: row.get("logsCount"),
            input: row.get("input"),
            value: row.get("value")
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionDetailsList {
    pub transactions: Vec<TransactionDetails>
}
impl TransactionDetailsList {
    pub fn new() -> Self {
        TransactionDetailsList {
            transactions: Vec::new()
        }
    }
    pub fn push(&mut self, details: TransactionDetails) {
        self.transactions.push(details);
    }
}