package com.thanhnguyen.security.constants;

public class CONSTANTS {
    public static final String MY_SECRET = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKT1NFIiwic3ViIjoidGhhbmgiLCJleHAiOjE2NzExODQ2NDEsImlhdCI6MTY3MTE4MTA0MSwicm9sZXMiOlsiUk9MRV9TVVBFUl9BRE1JTiIsIlJPTEVfVVNFUiJdfQ.40lvd5TTHJM4sSVNWLfh-kRR9QQZuw3Tjrl4qRRap9M";
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_SUPER_ADMIN = "ROLE_SUPER_ADMIN";
    public static final String ROLE_MANAGER = "ROLE_MANAGER";
    public static final Integer VALIDATION_TIME_ACCESS_TOKEN = 1000 * 60 * 60;
    public static final Integer VALIDATION_TIME_REFRESH_TOKEN = 1000 * 60 * 60 * 24 * 7;

}
