use tracing::error;

use serde::Deserialize;

use crate::types::{FetcherError, TransactionDetails, TransactionDetailsList};

// const URL_INFURA: &str = "https://mainnet.infura.io/v3/28d8b996e9174e82a7d049f4198deed1";

fn string_to_i32<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    match s.parse::<i32>() {
        Ok(i) => Ok(Some(i)),
        Err(_) => Ok(None)
    }
}

// Get data from internet, but if there is data in database then get from there
#[async_trait::async_trait]
pub trait EthFetcher {
    // pub fn get_transactions(&self) -> Vec<TransactionDetails>;
    // fn fetch_block_by_number(&self) -> BlockByNumberResp;
    fn new() -> Self;
    fn set_url(&mut self, url: &str);
    async fn fetch_transaction_details_list(&self, transaction_hashes: Vec<&str>) -> Result<TransactionDetailsList, FetcherError>;
    async fn fetch_transaction_details(&self, transaction_hash: &str) -> Result<TransactionDetails, FetcherError>;
}

// curl --url https://mainnet.infura.io/v3/28d8b996e9174e82a7d049f4198deed1   -X POST   -H "Content-Type: application/json"   -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest", false],"id":1}'
// {"jsonrpc":"2.0","id":1,"result":{"baseFeePerGas":"0x1084e4b0f", ..., 
//          "transactions":["0x43af9937a910b94c6eb00d37ac048c5cb74185872e99a2383b14c878ffab215a","0x95be5cd7f8dbb9deff47e9e327b0dd40ed5ed385ba71079d7652de55e87555c8","0x852114608bf1cdfb1f824ee30ad93aad397150220f8880e45587a996a5d49534", ...]}}
#[allow(dead_code)]
#[derive(Deserialize)]
struct TransactionsListResp {
    transactions: Vec<String>
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct BlockByNumberResp {
    result: TransactionsListResp
}

// curl --url https://mainnet.infura.io/v3/28d8b996e9174e82a7d049f4198deed1   -X POST   -H "Content-Type: application/json"   -d '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0x1c438d7a8b05b607e82c0c334a79cfb32eb2210a863ae38bb429ec71ac68ed4e"],"id":1}'
// "result":{"accessList":[],"blockHash":"0xf9c802cbacafa765325d2cdae96332394bc3336d14a96cba1e40e718a48d86f6","blockNumber":"0x14ab592","chainId":"0x1","from":"0x93793bd1f3e35a0efd098c30e486a860a0ef7551","gas":"0x49c4a","gasPrice":"0x2941dadcde","hash":"0x1c438d7a8b05b607e82c0c334a79cfb32eb2210a863ae38bb429ec71ac68ed4e","input":"0xa000000000000000000000000000000088e6a0c2ddd26feeb64f039a2c41296fcb3f56400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005746ad9a63234a7ff0000000000000000000000000000000000000000000000000000004d5ed2030d000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2","maxFeePerGas":"0x2941dadcde","maxPriorityFeePerGas":"0x2663efb973","nonce":"0x9684a","r":"0x612b7dd975dbf8552f5874f4698e7768b9d6acd1bb94fe053f1831157009da6f","s":"0x709d60b794bc33255c50d465846476c0b914508c1c2f8160d817f7e11ff3c596","to":"0x68d3a973e7272eb388022a5c6518d9b2a2e66fbf","transactionIndex":"0x0","type":"0x2","v":"0x0","value":"0x14ab592","yParity":"0x0"}
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct TransactionResultResp {
    #[serde(rename = "accessList")]
    access_list: Option<Vec<String>>,
    #[serde(rename = "blockHash")]
    block_hash: Option<String>,
    #[serde(rename = "blockNumber")]
    #[serde(deserialize_with = "string_to_i32")]
    block_number: Option<i32>,
    #[serde(rename = "chainId")]
    chain_id: String,
    from: String,
    gas: String,
    #[serde(rename = "gasPrice")]
    gas_price: String,
    hash: String,
    input: String,
    #[serde(rename = "maxFeePerGas")]
    max_fee_per_gas: Option<String>,
    #[serde(rename = "maxPriorityFeePerGas")]
    max_priority_fee_per_gas: Option<String>,
    nonce: String,
    r: String,
    s: String,
    to: Option<String>,
    #[serde(rename = "transactionIndex")]
    transaction_index: String,
    value: String,
}

#[derive(Deserialize, Debug)]
struct TransactionByHashResp {
    result: TransactionResultResp
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct TransactionReceiptLogItem{
    address: Option<String>,
}

#[derive(Deserialize)]
struct TransactionReceiptResultResp {
    #[serde(rename = "contractAddress")]
    contract_address: Option<String>,
    logs: Vec<TransactionReceiptLogItem>,
    status: String,
}

#[derive(Deserialize)]
struct TransactionReceiptResp {
    result: TransactionReceiptResultResp
}

trait EthFetcherPrivate {
    async fn fetch_transaction_by_hash(&self, transaction_hash: &str, result: &mut TransactionDetails) -> Result<(), FetcherError>;
    async fn fetch_receipt_by_hash(&self, transaction_hash: &str, result: &mut TransactionDetails) -> Result<(), FetcherError>;
}

pub struct EthTransactionsFetcher {
    url: String
}

impl EthFetcherPrivate for EthTransactionsFetcher {
    async fn fetch_transaction_by_hash(&self, transaction_hash: &str, result: &mut TransactionDetails) -> Result<(), FetcherError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionByHash",
            "params": [transaction_hash],
            "id": 1
        }); 
        let client = reqwest::Client::new();
        let res = match client.post(self.url.clone()).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                error!("Error fetching transaction details: {:?}", e);
                return Err(FetcherError::TransactionHashNetworkError(transaction_hash.to_string()));
            }
        };
        // I could use the res.json::<TransactionByHashResp>() but it does not give me details about 
        // the received buffer, so I will use res.text() instead
        // let resp_transaction: TransactionByHashResp = match res.json::<TransactionByHashResp>().await {
        let res_text = match res.text().await {
            Ok(r) => r,
            Err(e) => {
                error!("Error reading response of transaction details: {:?}", e);
                return Err(FetcherError::TransactionHashNetworkError(transaction_hash.to_string()));
            }
        };
        let resp_transaction: TransactionByHashResp = match serde_json::from_str(&res_text) {
            Ok(r) => r,
            Err(e) => {
                error!("Error parsing transaction details: {:?} text: {}", e, res_text);
                return Err(FetcherError::TransactionHashParsingError(transaction_hash.to_string()));
            }
        };

        let details = resp_transaction.result;
        result.transaction_hash = details.hash;
        result.block_hash = details.block_hash.as_ref().unwrap().to_string();
        result.block_number = details.block_number.unwrap_or(0);
        result.from = details.from;
        result.to = details.to;
        result.input = details.input;
        result.value = details.value;

        Ok(())
    }

    async fn fetch_receipt_by_hash(&self, transaction_hash: &str, result: &mut TransactionDetails) -> Result<(), FetcherError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [transaction_hash],
            "id": 1
        });
        let client = reqwest::Client::new();
        let res = match client.post(self.url.clone()).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                error!("Error fetching transaction receipt: {:?}", e);
                return Err(FetcherError::TransactionReceiptNetworkError(transaction_hash.to_string()));
            }
        };
        let resp_text = match res.text().await {
            Ok(r) => r,
            Err(e) => {
                error!("Error reading response of transaction receipt: {:?}", e);
                return Err(FetcherError::TransactionReceiptNetworkError(transaction_hash.to_string()));
            }
        };
        let resp_receipt: TransactionReceiptResp = match serde_json::from_str(&resp_text) {
            Ok(r) => r,
            Err(e) => {
                error!("Error parsing transaction receipt: {:?} text: {}", e, resp_text);
                return Err(FetcherError::TransactionReceiptParsingError(transaction_hash.to_string()));
            }
        };
        let receipt = resp_receipt.result;
        result.contract_address = receipt.contract_address;
        result.logs_count = receipt.logs.len() as i32;
        result.transaction_status = receipt.status;
        Ok(())
    }
}

#[async_trait::async_trait]
impl EthFetcher for EthTransactionsFetcher {
    fn new() -> Self {
        EthTransactionsFetcher {
            url: String::new()
        }
    }
    fn set_url(&mut self, url: &str) {
        self.url = url.to_string();
    }
    async fn fetch_transaction_details_list(&self, transaction_hashes: Vec<&str>) -> Result<TransactionDetailsList, FetcherError> {
        let mut details_list = TransactionDetailsList {
            transactions: Vec::new(),
        };
        for transaction_hash in transaction_hashes {
            let details = self.fetch_transaction_details(transaction_hash).await;
            if details.is_ok() {
                details_list.transactions.push(details.unwrap());
            } else {
                return Err(details.err().unwrap());
            }
        }
        Ok(details_list)
    }

    async fn fetch_transaction_details(&self, transaction_hash: &str) -> Result<TransactionDetails, FetcherError> {
        let mut details = TransactionDetails::new();

        let res = self.fetch_transaction_by_hash(transaction_hash, &mut details).await;
        if res.is_err() {
            return Err(res.err().unwrap());
        }
        let res = self.fetch_receipt_by_hash(transaction_hash, &mut details).await;
        if res.is_err() {
            return Err(res.err().unwrap());
        }
        Ok(details)
    }
}
