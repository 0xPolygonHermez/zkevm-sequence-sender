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
  "0x83014454cfd2989e8a82f31fce6f2eff19a3d44886cb36b365ee4d1cd6b159f3": {
    "nonce": 116,
    "status": "finalized",
    "sentL1Timestamp": "2024-02-09T11:09:00.04870821+01:00",
    "statusTimestamp": "2024-02-09T11:15:29.623881059+01:00",
    "fromBatch": 483,
    "toBatch": 483,
    "minedAtBlock": 5251050,
    "onMonitor": true,
    "to": "0x31a6ae85297dd0eebd66d7556941c33bd41d565c",
    "stateHistory": [
      "2024-02-09T11:09:00.048+01:00, *new, created",
      "2024-02-09T11:09:14.624+01:00, created, sent",
      "2024-02-09T11:11:14.629+01:00, sent, mined",
      "2024-02-09T11:13:14.625+01:00, mined, consolidated",
      "2024-02-09T11:15:29.623+01:00, consolidated, finalized"
    ],
    "txs": {
      "0x3876149295d876b09e92900d3fba2986d89c0572f8f7d345fa2ce8f058267282": {
        "gasPrice": 4426444863
      }
    }
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
