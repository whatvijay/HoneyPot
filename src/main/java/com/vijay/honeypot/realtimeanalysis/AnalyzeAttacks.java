package com.vijay.honeypot.realtimeanalysis;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.vijay.honeypot.entities.RequestsInfo;
import com.vijay.honeypot.repository.RequestInfoRepo;
@Component
public class AnalyzeAttacks {

	@Autowired
	RequestInfoRepo requestInfoRepo;
	@Autowired
	private JavaMailSender sender;

	@Scheduled(fixedRate = 5000)
	public void analyzeAttacks() {
		List<RequestsInfo> reqList = requestInfoRepo.findAllByProcessedEquals(false);
		
		if(null != reqList)
		{
		Map<String, Integer> ipCountMap = new HashMap<>();
		for (RequestsInfo reqInfo : reqList) {

			// check for ddos
			String ipAddr = reqInfo.getIpAddr();
			int count = 0;
			if (ipCountMap.containsKey(ipAddr)) {
				count = ipCountMap.get(ipAddr) + 1;
				ipCountMap.put(ipAddr, count);

			} else {
				ipCountMap.put(ipAddr, 1);
			}
			reqInfo.setProcessed(true);
			requestInfoRepo.save(reqInfo);
		}
		for (Entry<String, Integer> e : ipCountMap.entrySet()) {
			if (e.getValue() > 50) {
				SimpleMailMessage message = new SimpleMailMessage();

				message.setFrom("");
				message.setTo("");
				message.setSubject("DDOS is detected");
				message.setText(
						"DDOS from " + e.getKey() + " detected pings between scheduled interval " + e.getValue());
				sender.send(message);
			}
		}
	}
	}
}
