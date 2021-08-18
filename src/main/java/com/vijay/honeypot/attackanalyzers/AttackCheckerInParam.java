package com.vijay.honeypot.attackanalyzers;
/*
 * 
 */
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

@Component
public class AttackCheckerInParam {

	public boolean checkForSqlInjectionAttack(String param) {
		Pattern[] patterns = new Pattern[] {
				// Script fragments
				Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE),
				// src='...'
				Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'",
						Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
				Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"",
						Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
				// lonely script tags
				Pattern.compile("</script>", Pattern.CASE_INSENSITIVE),
				Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
				// eval(...)
				Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
				// expression(...)
				Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
				// javascript:...
				Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
				// vbscript:...
				Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE),
				// onload(...)=...
				Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL) };

		for (Pattern pattern : patterns) {
			if (pattern.matcher(param).find()) {
				return true;
			}
		}
		return false;
	}

}
