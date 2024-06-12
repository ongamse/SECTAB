package io.shiftleft.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;


/**
 * Search login
 */
@Controller
public class SearchController {

  @RequestMapping(value = "/search/user", method = RequestMethod.GET)
	@RequestMapping(value = "/search/user", method = RequestMethod.GET)
	public String doGetSearch(@RequestParam String foo, HttpServletResponse response, HttpServletRequest request) {
		try {
			// Removed the instantiation of a new Object() and the use of SpEL.
			// Instead, we will use a whitelist to validate the input.
			String[] whitelist = {"foo", "bar", "baz"};
			if (!Arrays.asList(whitelist).contains(foo)) {
				throw new IllegalArgumentException("Invalid parameter: " + foo);
			}
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
			return "Error: " + ex.getMessage();
		}
		return "Valid parameter: " + foo;
	}


