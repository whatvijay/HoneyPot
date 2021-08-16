package com.vijay.honeypot.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.vijay.honeypot.entities.RequestsInfo;

@Repository
public interface RequestInfoRepo extends JpaRepository<RequestsInfo, Long> {
	List<RequestsInfo> findAllByProcessedEquals(Boolean process);
}
