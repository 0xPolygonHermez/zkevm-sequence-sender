# zkevm-sequence-sender
Stateless autonomous binary to sequence L2 batches and send them to L1.

## Architecture
![Diagram](docs/sequencesender.drawio.png)

- **Sequence Sender**: Gets batches from the datastream, detects when they have been closed, and aggregates as many of them as possible. Then decides the time to send those batches to L1 to get its state to transition to virtualized.

- **JSON file**: Persistence of transactions sent to L1. It is used as a cache for transaction management.

- **Datastream client**: Sequence Sender uses the stream client implemented in the [data streamer](https://github.com/0xPolygonHermez/zkevm-data-streamer) library to connect to a datastream server.

- **Datastream server**: The data source is a datastream server, so the SequenceSender connects to the stream server to get information about L2 transactions, blocks, and batches.

- **EthTxManager**: [Library](https://github.com/0xPolygonHermez/zkevm-ethtx-manager) used for sending and monitoring L1 transactions.


## File
An example of the content of the JSON persistence file.
```
{
  "0x602c800c4f7a9c95877ced446f67997f4c3f19940b42a18116976395319e0697": {
    "nonce": 19,
    "status": "mined",
    "sentL1Timestamp": "2024-02-07T10:04:37.628391558+01:00",
    "statusTimestamp": "2024-02-07T10:04:52.612031307+01:00",
    "fromBatch": 3,
    "toBatch": 3,
    "minedAtBlock": 196,
    "onMonitor": true,
    "to": "0x8daf17a20c9dba35f005b6324f493785d239719d",
    "txs": {
      "0x46b57b78245c2678d6d03396f6e11db5cfd5ef6147e83d089e62722a19cb86e3": {
        "revertMessage": ""
      }
    }
  },
  "0xc6bd02700b9456842503bb05a878f6b049b49eb863c77ca47bd526bb4ee53985": {
    "nonce": 20,
    "status": "created",
    "sentL1Timestamp": "2024-02-07T10:05:07.631269379+01:00",
    "statusTimestamp": "2024-02-07T10:05:07.631286009+01:00",
    "fromBatch": 4,
    "toBatch": 4,
    "minedAtBlock": 0,
    "onMonitor": true,
    "to": "0x8daf17a20c9dba35f005b6324f493785d239719d",
    "txs": {}
  }
}
```


## Config
To the existing configuration in the SequenceSender from the [Node](https://github.com/0xPolygonHermez/zkevm-node), the following configuration parameters have been added.

Wait time for a finalized transaction to be purged from the persistence file:
```
[SequenceSender]
WaitPeriodPurgeTxFile=48h
```

Maximum number of transactions pending completion. Once this number is reached, no new transactions will be sent until one completes:
```
[SequenceSender]
MaxPendingTx=1
```
