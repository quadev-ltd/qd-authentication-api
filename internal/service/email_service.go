package service

import (
	"fmt"
	"net/smtp"
)

type EmailServiceConfig struct {
	AppName  string
	BaseUrl  string
	From     string
	Password string
	Host     string
	Port     string
}

type EmailServicer interface {
	SendVerificationMail(dest string, userName, verificationToken string) error
}

type EmailService struct {
	config EmailServiceConfig
	sender SmtpServicer
}

var _ EmailServicer = &EmailService{}

func NewEmailService(config EmailServiceConfig, sender SmtpServicer) *EmailService {

	return &EmailService{
		config: config,
		sender: &SmtpService{},
	}
}

func (service *EmailService) sendMail(dest string, subject string, body string) error {
	message := "From: " + service.config.From + "\n" +
		"To: " + dest + "\n" +
		"Subject: " + subject + "\n\n" +
		body
	config := service.config
	auth := smtp.PlainAuth("", config.From, config.Password, config.Host)
	resultError := smtp.SendMail(
		fmt.Sprintf("%s:%s", config.Host, config.Port),
		auth,
		config.From, []string{dest}, []byte(message))
	return resultError
}

func (service *EmailService) CreateVerificationEmailContent(destination string, userName, verificationToken string) (string, string) {
	subject := fmt.Sprintf("Welcome to %s", service.config.AppName)
	body := fmt.Sprintf("Hi %s,\nYou've just signed up to %s!\nWe need to verify your email.\nPlease click on the following link to verify your account:\n%s\n\nThanks.", userName, service.config.AppName, service.config.BaseUrl+"/verify/"+verificationToken)
	return subject, body
}

func (service *EmailService) SendVerificationMail(destination string, userName, verificationToken string) error {
	subject, body := service.CreateVerificationEmailContent(destination, userName, verificationToken)
	error := service.sendMail(destination, subject, body)
	return error
}
