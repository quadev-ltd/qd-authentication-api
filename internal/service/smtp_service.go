package service

import "net/smtp"

// SMTPServicer is the interface for the smtp service dependency injection
type SMTPServicer interface {
	SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error
	PlainAuth(identity, from, password, host string) smtp.Auth
}

// SMTPService is the implementation of the smtp service dependency injection
type SMTPService struct{}

var _ SMTPServicer = &SMTPService{}

// SendMail sends an email
func (smtp *SMTPService) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, a, from, to, msg)
}

// PlainAuth returns an Auth that implements the PLAIN authentication mechanism
func (smtp *SMTPService) PlainAuth(identity, username, password, host string) smtp.Auth {
	return smtp.PlainAuth(identity, username, password, host)
}
