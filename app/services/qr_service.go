package services

import (
	"encoding/base64"

	"github.com/skip2/go-qrcode"
)

type QRService struct{}

// NewQRService creates a new QR code service
func NewQRService() *QRService {
	return &QRService{}
}

// GenerateQRCode generates a QR code PNG image from a URL
func (s *QRService) GenerateQRCode(url string) ([]byte, error) {
	qr, err := qrcode.Encode(url, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	return qr, nil
}

// GenerateQRCodeBase64 generates a QR code and returns it as base64 encoded PNG
func (s *QRService) GenerateQRCodeBase64(url string) (string, error) {
	qrBytes, err := s.GenerateQRCode(url)
	if err != nil {
		return "", err
	}

	// Convert to base64
	return base64.StdEncoding.EncodeToString(qrBytes), nil
}

// GenerateQRCodeDataURL generates a QR code and returns it as a data URL
func (s *QRService) GenerateQRCodeDataURL(url string) (string, error) {
	qrBytes, err := s.GenerateQRCode(url)
	if err != nil {
		return "", err
	}

	// Create data URL
	base64Data := base64.StdEncoding.EncodeToString(qrBytes)
	dataURL := "data:image/png;base64," + base64Data
	return dataURL, nil
}
