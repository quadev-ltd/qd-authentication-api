package service

import "net/smtp"

type SmtpServicer interface {
	SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error
	PlainAuth(identity, from, password, host string) smtp.Auth
}

type SmtpService struct{}

var _ SmtpServicer = &SmtpService{}

func (smtp *SmtpService) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, a, from, to, msg)
}

func (smtp *SmtpService) PlainAuth(identity, username, password, host string) smtp.Auth {
	return smtp.PlainAuth(identity, username, password, host)
}
