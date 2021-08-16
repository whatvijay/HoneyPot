package com.vijay.honeypot.api;

import java.time.LocalDateTime;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vijay.honeypot.attackanalyzers.AttackCheckerInParam;
import com.vijay.honeypot.entities.RequestsInfo;
import com.vijay.honeypot.repository.RequestInfoRepo;

@RestController
@CrossOrigin
@RequestMapping("/userDetails")
public class UserDetails {

	@Autowired
	AttackCheckerInParam attackChecker;

	@Autowired
	RequestInfoRepo requestInfoRepo;

	@GetMapping("/getuserDetailsById/{id}")
	public String getUserDetailsById(@PathVariable String id, HttpServletRequest httpServletRequest) {

		// check for an attack but return a response

		if (attackChecker.checkForSqlInjectionAttack(id)) {

			RequestsInfo reqInfo = new RequestsInfo();
			reqInfo.setIpAddr(httpServletRequest.getRemoteAddr());
			reqInfo.setRequestInfo(httpServletRequest.getRequestURI());
			reqInfo.setAttackDetected(true);
			reqInfo.setRequestTime(LocalDateTime.now());
			reqInfo.setProcessed(false);
			requestInfoRepo.save(reqInfo);

			return "id not found";

		} else {
			RequestsInfo reqInfo = new RequestsInfo();
			reqInfo.setIpAddr(httpServletRequest.getRemoteAddr());
			reqInfo.setRequestInfo(httpServletRequest.getRequestURI());
			reqInfo.setAttackDetected(false);
			reqInfo.setRequestTime(LocalDateTime.now());
			reqInfo.setProcessed(false);
			requestInfoRepo.save(reqInfo);
			return "id not found";
		}
	}
}
