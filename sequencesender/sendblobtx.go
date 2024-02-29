package sequencesender

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"os"
	"path/filepath"

	"github.com/0xPolygonHermez/zkevm-sequence-sender/log"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func (s *SequenceSender) createSendBlobTx(ctx context.Context, maxPrioFee uint64, maxFeePerGas uint64, maxBlobFee uint64, gasLimit uint64, value uint64, data []byte, blobData []string) error {
	// Blob transaction
	txData := types.BlobTx{
		GasTipCap:  uint256.NewInt(maxPrioFee * 1000000000),   // nolint:gomnd // maxPriorityFeePerGas
		GasFeeCap:  uint256.NewInt(maxFeePerGas * 1000000000), // nolint:gomnd // maxFeePerGas
		BlobFeeCap: uint256.NewInt(maxBlobFee * 1000000000),   // nolint:gomnd // maxFeePerBlobGas
		Gas:        gasLimit,
		To:         common.HexToAddress(s.etherman.SCAddresses[0].Hex()),
		Value:      uint256.NewInt(value),
		Data:       data,
		BlobHashes: make([]common.Hash, 0),
		Sidecar: &types.BlobTxSidecar{
			Blobs:       make([]kzg4844.Blob, 0),
			Commitments: make([]kzg4844.Commitment, 0),
			Proofs:      make([]kzg4844.Proof, 0),
		},
	}

	// Blob data
	var blobBytes []byte
	for _, blob := range blobData {
		blobBytes = append(blobBytes, common.FromHex(blob)...)
	}
	blob, err := encodeBlobData(blobBytes)
	if err != nil {
		return err
	}

	// Blob commitment
	blobCommitment, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		log.Errorf("failed generating blob commitment: %v", err)
		return err
	}

	// Blob proof
	blobProof, err := kzg4844.ComputeBlobProof(blob, blobCommitment)
	if err != nil {
		log.Errorf("failed generating blob proof: %v", err)
		return err
	}

	// Blob versioned hash
	blobVerHash := sha256.Sum256(blobCommitment[:])
	blobVerHash[0] = 0x01 // params.BlobTxHashVersion // Version byte of the commitment hash

	// Sidecar
	txData.BlobHashes = append(txData.BlobHashes, blobVerHash)
	txData.Sidecar.Blobs = append(txData.Sidecar.Blobs, blob)
	txData.Sidecar.Commitments = append(txData.Sidecar.Commitments, blobCommitment)
	txData.Sidecar.Proofs = append(txData.Sidecar.Proofs, blobProof)

	// Tx
	txData.ChainID = uint256.NewInt(s.cfg.EthTxManager.Etherman.L1ChainID)
	txData.Nonce = s.currentNonce

	tx := types.NewTx(&txData)
	key, err := newKeyFromKeystore(s.cfg.PrivateKey.Path, s.cfg.PrivateKey.Password)
	if err != nil {
		log.Errorf("failed reading from keystore: %v", err)
		return err
	}

	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(int64(s.cfg.EthTxManager.Etherman.L1ChainID))), key.PrivateKey)
	if err != nil {
		log.Errorf("failed signing tx: %v", err)
		return err
	}
	log.Infof("%+v", signedTx)

	// Send transaction
	err = s.etherman.SendTx(ctx, signedTx)
	if err != nil {
		log.Errorf("failed sending tx %v: %v", signedTx.Hash().String(), err)
		return err
	}
	log.Infof("signed tx sent: %v", signedTx.Hash().String())

	return nil
}

func encodeBlobData(data []byte) (kzg4844.Blob, error) {
	dataLen := len(data)
	if dataLen > params.BlobTxFieldElementsPerBlob*(params.BlobTxBytesPerFieldElement-1) {
		log.Errorf("blob data longer than allowed (length: %v, limit: %v)", dataLen, params.BlobTxFieldElementsPerBlob*(params.BlobTxBytesPerFieldElement-1))
		return kzg4844.Blob{}, errors.New("blob data longer than allowed")
	}

	// 1 Blob = 4096 Field elements x 32 bytes/field element = 128 KB
	elemSize := params.BlobTxBytesPerFieldElement

	blob := kzg4844.Blob{}
	fieldIndex := -1
	for i := 0; i < len(data); i += (elemSize - 1) {
		fieldIndex++
		if fieldIndex == params.BlobTxFieldElementsPerBlob {
			break
		}
		max := i + (elemSize - 1)
		if max > len(data) {
			max = len(data)
		}
		copy(blob[fieldIndex*elemSize+1:], data[i:max])
	}
	return blob, nil
}

func newKeyFromKeystore(path, password string) (*keystore.Key, error) {
	if path == "" && password == "" {
		return nil, nil
	}
	keystoreEncrypted, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	log.Infof("decrypting key from: %v", path)
	key, err := keystore.DecryptKey(keystoreEncrypted, password)
	if err != nil {
		return nil, err
	}
	return key, nil
}
