# The Ethereum Fetcher - REST Server

This project is a backend web service implemented in Rust using Axum as the web framework. The service interacts with a PostgreSQL database, processes and stores blockchain-related data, and provides an API for managing these records.

**See Quick Start with examples below**

## The main functionality includes:

- Inserting and retrieving transaction hashes.
- Storing user interactions with blockchain data.
- Ensuring data consistency via database constraints and triggers.
- Running automated tests using a separate test database instance.
The system is designed to be efficient, secure, and easily testable using Docker-based environments.

# Architecture of the Server – Design Decisions and Overview
The architecture follows a modular, layered approach, ensuring separation of concerns and scalability.
- HTTP API (Axum) --  Handles requests, routes, and authentication
- Service Layer -- Business logic, request validation, and processing
- Database Abstraction -- Queries, transactions, and DB management (tokio_postgres)
- PostgreSQL DB -- Persistent storage for blockchain data

## Key Design Decisions
* Web Framework: Axum
  Chosen for performance, async support (Tokio), and compatibility with Rust's ecosystem.
  Routes are structured in a modular way to support API versioning and extensibility.

* Database: PostgreSQL + tokio_postgres
  PostgreSQL is used for data integrity, relational queries, and support for constraints.
  The tokio_postgres async driver ensures efficient query execution.

## Database Schema Design
* hash_data: Stores blockchain transactions.
* hash_logs: Tracks which users accessed which transactions.
* Constraints like ON DELETE CASCADE ensure referential integrity.

## Query Execution Strategy

* Uses prepared statements to avoid SQL injection.
* Queries are executed asynchronously for high performance.

## Environment Management

* Separate databases for production and testing to prevent test interference.

## Docker-Based Deployment

* The main app and database run in Docker containers (docker-compose.yml).
* A separate test database (docker-compose.test.yml) ensures isolation for cargo test.

## Testing Strategy

* Unit tests for the database layer.
* Integration tests run against a dedicated PostgreSQL test instance.
* #[cfg(test)] is used for conditional compilation of test-related code.

## Implemented endpoints
* GET `/lime/eth?transactionHashes=...`
* GET `/lime/eth/{:rlphex}`
* GET `/lime/all`
* GET `/lime/my`
* POST `/lime/authenticate`

# Build the application

## Rust build 

This is a Rust project so use regular approach if you need to build the application out of docker container.
* `cargo build`              - for debug build
* `cargo build --release`    - for release build

## Docker build

* `docker build -t limeapi .`         - build docker image of web server by docker directly

# How to run the server

The server may be run by different ways:

1. Run database in docker and run the server by usual Rust way
* `docker compose up -d db`        - run the database in docker container in daemon mode
* `cargo run`                      - run the web server by regular Rust way

2. Run database and web server in docker container with building of web server
* `docker compose up --build`      - run the database and build & run the web server 

By this way you are building the docker image and running the docker container in one command. 
You will be able to see debug output from docker container of web server.

3. Run database and web server in docker container as daemon (without output)
* `docker compose up -d`

By this way you can run database and web server containers in daemon mode (on background), so you will not see debug messages from the web server. This way may be used if you have built the docker image of web server preliminary (see commands above).

4. Run database and web server in docker container in regular mode
* `docker compose up`

By this way you will run database and web server in containers and will be able to see debug output.
This way is preferred if you have an image of web server and want to see debug messages.

5. Prepare for testing and run all tests
* `docker compose up -d`        - run web server with database in daemon mode to be able to continue using the same console
* `docker compose -f docker-compose.test.yml up -d`   - run the test database container
* `cargo test`

Pay attention that the test mode may be used at the same time when the web server works in its regular mode. The test database container exposes port `5433` that is why we can use both containers (regular and test one) simultaneously.

# Requests and Responses Examples

## POST /lime/authenticate
- POST http://localhost:3000/lime/authenticate
Body: 
{
  "username": "alice",
  "password": "alice"
}
Response:
{
  "token": "eyJ0eXAiOiJK[HIDDEN]Gn9XdzxRlNC8CFhNfvjqdbfvQ"
}

## GET /lime/eth?transactionHashes without header AUTH_TOKEN
- GET http://localhost:3000/lime/eth?transactionHashes=0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327&transactionHashes=0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3

Response: 200 OK
```jsx
{
  "transactions": [
    {
      "transactionHash": "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0xed69cf1ba4fcf0298880133b1117469682dd00f9",
      "to": "0x2e5e2f0103814bb751d44880e6d36fa24f95b7fe",
      "contractAddress": null,
      "logsCount": 0,
      "input": "0x",
      "value": "0x3c6caf9657000"
    },
    {
      "transactionHash": "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0xeaea44678db76e31fe1d8db18eeb746ee4af1717",
      "to": "0x84e717025caa84016b8998a12d8da9cbf8a8d6e8",
      "contractAddress": null,
      "logsCount": 3,
      "input": "0x00007ba60392ffffff467bccd9d29f223bce8043b84e8c8b282827790f2494f588028333900101f359492d26764481002ed88bd2acae83ca50b5c90bb8",
      "value": "0x0"
    }
  ]
}
```

## GET /lime/eth?transactionHashes with header AUTH_TOKEN
- GET http://localhost:3000/lime/eth?transactionHashes=0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370
Headers: AUTH_TOKEN - get token from result of /lime/authenticate

Response: 200 OK
```jsx
{
  "transactions": [
    {
      "transactionHash": "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0x568285d767c2da2fd42d33c2507a1ecb98fe0d28",
      "to": "0xf2139f5c8afb8a4d64084efc5532830774742830",
      "contractAddress": null,
      "logsCount": 1,
      "input": "0xdfda7570ff69a44f5259a060d3901698200201c372103089aaae133ebfd55621806e925a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000036cf96470000000000000000000000001b3d00515f7bf0e9bd7eef7213ef17b166c19aa500000000000000000000000000000000000000000000000000000000000002f1",
      "value": "0x0"
    }
  ]
}
```

## GET /lime/all
- GET http://localhost:3000/lime/all

Response: 200 OK
```jsx
{
  "transactions": [
    {
      "transactionHash": "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0xed69cf1ba4fcf0298880133b1117469682dd00f9",
      "to": "0x2e5e2f0103814bb751d44880e6d36fa24f95b7fe",
      "contractAddress": null,
      "logsCount": 0,
      "input": "0x",
      "value": "0x3c6caf9657000"
    },
    {
      "transactionHash": "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0xeaea44678db76e31fe1d8db18eeb746ee4af1717",
      "to": "0x84e717025caa84016b8998a12d8da9cbf8a8d6e8",
      "contractAddress": null,
      "logsCount": 3,
      "input": "0x00007ba60392ffffff467bccd9d29f223bce8043b84e8c8b282827790f2494f588028333900101f359492d26764481002ed88bd2acae83ca50b5c90bb8",
      "value": "0x0"
    },
    {
      "transactionHash": "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0x568285d767c2da2fd42d33c2507a1ecb98fe0d28",
      "to": "0xf2139f5c8afb8a4d64084efc5532830774742830",
      "contractAddress": null,
      "logsCount": 1,
      "input": "0xdfda7570ff69a44f5259a060d3901698200201c372103089aaae133ebfd55621806e925a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000036cf96470000000000000000000000001b3d00515f7bf0e9bd7eef7213ef17b166c19aa500000000000000000000000000000000000000000000000000000000000002f1",
      "value": "0x0"
    }
  ]
}
```

## GET /lime/my
- GET http://localhost:3000/lime/my

Response: 200 OK
```jsx
{
  "transactions": [
    {
      "transactionHash": "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0x568285d767c2da2fd42d33c2507a1ecb98fe0d28",
      "to": "0xf2139f5c8afb8a4d64084efc5532830774742830",
      "contractAddress": null,
      "logsCount": 1,
      "input": "0xdfda7570ff69a44f5259a060d3901698200201c372103089aaae133ebfd55621806e925a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000036cf96470000000000000000000000001b3d00515f7bf0e9bd7eef7213ef17b166c19aa500000000000000000000000000000000000000000000000000000000000002f1",
      "value": "0x0"
    }
  ]
}
```

## GET /lime/eth/{:rlphex}

- GET http://localhost:3000/lime/eth/f8ccb842307865356664616430336234323239383232623139303934626566633431386466363035356231303237323337643438393137656338336337613062343237333237b842307830626239363737326536326432376665636130643339323563383365306462653932396138633037323831343335623039663133653436663439633233636133b842307839623832356265616637653165373932333062633965306637316134633065393835326436343566656636383865326664633331303462343862323738333730

**Without optional AUTH_TOKEN**

Response: 200 OK
```jsx
{
  "transactions": [
    {
      "transactionHash": "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0xed69cf1ba4fcf0298880133b1117469682dd00f9",
      "to": "0x2e5e2f0103814bb751d44880e6d36fa24f95b7fe",
      "contractAddress": null,
      "logsCount": 0,
      "input": "0x",
      "value": "0x3c6caf9657000"
    },
    {
      "transactionHash": "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0xeaea44678db76e31fe1d8db18eeb746ee4af1717",
      "to": "0x84e717025caa84016b8998a12d8da9cbf8a8d6e8",
      "contractAddress": null,
      "logsCount": 3,
      "input": "0x00007ba60392ffffff467bccd9d29f223bce8043b84e8c8b282827790f2494f588028333900101f359492d26764481002ed88bd2acae83ca50b5c90bb8",
      "value": "0x0"
    },
    {
      "transactionHash": "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0x568285d767c2da2fd42d33c2507a1ecb98fe0d28",
      "to": "0xf2139f5c8afb8a4d64084efc5532830774742830",
      "contractAddress": null,
      "logsCount": 1,
      "input": "0xdfda7570ff69a44f5259a060d3901698200201c372103089aaae133ebfd55621806e925a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000036cf96470000000000000000000000001b3d00515f7bf0e9bd7eef7213ef17b166c19aa500000000000000000000000000000000000000000000000000000000000002f1",
      "value": "0x0"
    }
  ]
}
```
After this request without AUTH_TOKEN the GET /lime/my will be returning the same response with one item

```jsx
{
  "transactions": [
    {
      "transactionHash": "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0x568285d767c2da2fd42d33c2507a1ecb98fe0d28",
      "to": "0xf2139f5c8afb8a4d64084efc5532830774742830",
      "contractAddress": null,
      "logsCount": 1,
      "input": "0xdfda7570ff69a44f5259a060d3901698200201c372103089aaae133ebfd55621806e925a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000036cf96470000000000000000000000001b3d00515f7bf0e9bd7eef7213ef17b166c19aa500000000000000000000000000000000000000000000000000000000000002f1",
      "value": "0x0"
    }
  ]
}
```

If you run the same request with AUTH_TOKEN for `alice` then after this the GET /lime/my will be returning all 3 items:

```jsx
{
  "transactions": [
    {
      "transactionHash": "0xe5fdad03b4229822b19094befc418df6055b1027237d48917ec83c7a0b427327",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0xed69cf1ba4fcf0298880133b1117469682dd00f9",
      "to": "0x2e5e2f0103814bb751d44880e6d36fa24f95b7fe",
      "contractAddress": null,
      "logsCount": 0,
      "input": "0x",
      "value": "0x3c6caf9657000"
    },
    {
      "transactionHash": "0x0bb96772e62d27feca0d3925c83e0dbe929a8c07281435b09f13e46f49c23ca3",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0xeaea44678db76e31fe1d8db18eeb746ee4af1717",
      "to": "0x84e717025caa84016b8998a12d8da9cbf8a8d6e8",
      "contractAddress": null,
      "logsCount": 3,
      "input": "0x00007ba60392ffffff467bccd9d29f223bce8043b84e8c8b282827790f2494f588028333900101f359492d26764481002ed88bd2acae83ca50b5c90bb8",
      "value": "0x0"
    },
    {
      "transactionHash": "0x9b825beaf7e1e79230bc9e0f71a4c0e9852d645fef688e2fdc3104b48b278370",
      "transactionStatus": "0x1",
      "blockHash": "0xd6469798c8fe49de846022b6561ba27e0ddb56c30713a285caec9dfaf3956d28",
      "blockNumber": 0,
      "from": "0x568285d767c2da2fd42d33c2507a1ecb98fe0d28",
      "to": "0xf2139f5c8afb8a4d64084efc5532830774742830",
      "contractAddress": null,
      "logsCount": 1,
      "input": "0xdfda7570ff69a44f5259a060d3901698200201c372103089aaae133ebfd55621806e925a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000036cf96470000000000000000000000001b3d00515f7bf0e9bd7eef7213ef17b166c19aa500000000000000000000000000000000000000000000000000000000000002f1",
      "value": "0x0"
    }
  ]
}
```

## The list of transactionHashes which you can use for testing

0x734635ba5e8988d289932b069c400f054161de3050b93a1e2cbfdd8d32bfef64
0x863ca84e56bccf0b806521ec64e3188176462becf5a1d61065f4057a9f0b2317
0x8d5f9edda7ea34d2388326bc7a9a2e1c801a53527cc0a806b1c321b3d72718f9
0x298b189be79c73d0fc20839cd569a2294a9451f32578b92df8b37d2a1b79f2df
0xbe917549376d4bc7d5f10a3c5f7150fe2a23bf3950bcd1fe9a851502d8fe7982
0x792f6c060ba3a7742cf7d9e12dee2ab527cbf969fb0858bab1646591fe306d8a
0x26bda294465e64e0ae929d0ce2f5cfa2f02a9801f943313ccfb192ce4257d49c
0xe3a83ed35c9c59b83daf515cc2e91be4ecf75c694afe4e10b003ce8545b33a18


# Quick Start

This is a brief list of steps to prepare web server for using its functionality.
These steps should be performed after cloning of the project to your local machine.

## Build and Start Database and Web server containers
1. `docker build -t limeapi .`
2. `docker compose up`
Now go to `Requests and Responses Examples` and send requests one by one to check how the web server works.
**Press `Ctrl+C` to stop the containers**

For example, to check the list of users run:
`psql -p 5432 -h localhost -U postgres -d postgres -c "SELECT * FROM users"`
password is `postgres`

## Running unit tests
1. `docker compose -f docker-compose.test.yml up -d`
2. `cargo test`
The test database is created with such parameters:
user: `testuser`
password: `testpass`
db_name: `testdb`
Check the list of users:
`psql -p 5433 -h localhost -U testuser -d testdb -c "SELECT * FROM users"`


## Stop all containers
1. `docker compose -f docker-compose.test.yml down`
2. `docker compose down`
