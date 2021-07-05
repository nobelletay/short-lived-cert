package main

import (
	"encoding/hex"
	"fmt"
	"time"
)

func Date(year, month, day int) time.Time {
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}

func (ca *Server) gen_day_key(domain_name string, time string) (encrypt_key [32]uint8) {
	// DO NOT CHANGE
	// year, month, day := time.Now().Date()
	// fmt.Println(year, month, day)
	// t_now := Date(year, int(month), day)
	// t_start := ca.first_start_time
	// days := t_now.Sub(t_start).Hours() / 24
	// fmt.Println(days)

	// salt := domain_name + time.Time.String(ca.first_start_time.AddDate(0, 0, int(days)))
	salt := domain_name + time
	encrypt_key = kdf(ca.master_key, salt)
	return encrypt_key
}

func (ca *Server) main_daykey(domain_name string, time string) string {
	fmt.Println("domain name: " + domain_name)
	key := ca.gen_day_key(domain_name, time)
	daily_key := hex.EncodeToString(key[:])

	return daily_key
}
