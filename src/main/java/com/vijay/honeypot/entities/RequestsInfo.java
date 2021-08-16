package com.vijay.honeypot.entities;

import java.time.LocalDateTime;

import javax.persistence.*;

import lombok.Data;

@Entity
@Table(name = "REQUESTSINFO")
@Data
public class RequestsInfo {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private long id;

	@Column(name = "IP_ADDR")
	private String ipAddr;

	@Column(name = "REQUEST_INFO")
	private String requestInfo;

	@Column(name = "ATTACK_DETECTED")
	private boolean attackDetected;

	@Column(name = "processed")
	private boolean processed;

	@Column(name = "REQUEST_TIME")
	private LocalDateTime requestTime;

	public boolean isProcessed() {
		return processed;
	}

	public void setProcessed(boolean processed) {
		this.processed = processed;
	}

	public LocalDateTime getRequestTime() {
		return requestTime;
	}

	public void setRequestTime(LocalDateTime requestTime) {
		this.requestTime = requestTime;
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getIpAddr() {
		return ipAddr;
	}

	public void setIpAddr(String ipAddr) {
		this.ipAddr = ipAddr;
	}

	public String getRequestInfo() {
		return requestInfo;
	}

	public void setRequestInfo(String requestInfo) {
		this.requestInfo = requestInfo;
	}

	public boolean isAttackDetected() {
		return attackDetected;
	}

	public void setAttackDetected(boolean attackDetected) {
		this.attackDetected = attackDetected;
	}

}
