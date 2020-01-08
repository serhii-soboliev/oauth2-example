package com.dataart.oidc.userinfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

public class DataArtOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private static final Logger LOG = LoggerFactory.getLogger(DataArtOidcUserService.class);

    private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = new DefaultOAuth2UserService();

    private static final Converter<Map<String, Object>, Map<String, Object>> DEFAULT_CLAIM_TYPE_CONVERTER =
            new ClaimTypeConverter(createDefaultClaimTypeConverters());

    private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory =
            clientRegistration -> DEFAULT_CLAIM_TYPE_CONVERTER;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");
        OidcUserInfo userInfo = null;
        if (shouldRetrieveUserInfo()) {
            OAuth2User oauth2User = this.oauth2UserService.loadUser(userRequest);

            Map<String, Object> claims;
            Converter<Map<String, Object>, Map<String, Object>> claimTypeConverter =
                    this.claimTypeConverterFactory.apply(userRequest.getClientRegistration());
            if (claimTypeConverter != null) {
                claims = claimTypeConverter.convert(oauth2User.getAttributes());
            } else {
                claims = DEFAULT_CLAIM_TYPE_CONVERTER.convert(oauth2User.getAttributes());
            }
            userInfo = new OidcUserInfo(claims);
            if (userInfo.getSubject() == null) {
                OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }

            if (!userInfo.getSubject().equals(userRequest.getIdToken().getSubject())) {
                OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new OidcUserAuthority(userRequest.getIdToken(), userInfo));
        OAuth2AccessToken token = userRequest.getAccessToken();
        for (String authority : token.getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
        }

        OidcUser user;

        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        if (StringUtils.hasText(userNameAttributeName)) {
            user = new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo, userNameAttributeName);
        } else {
            user = new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo);
        }

        return user;
    }

    public static Map<String, Converter<Object, ?>> createDefaultClaimTypeConverters() {
        Converter<Object, ?> booleanConverter = getConverter(TypeDescriptor.valueOf(Boolean.class));
        Converter<Object, ?> instantConverter = getConverter(TypeDescriptor.valueOf(Instant.class));

        Map<String, Converter<Object, ?>> claimTypeConverters = new HashMap<>();
        claimTypeConverters.put(StandardClaimNames.EMAIL_VERIFIED, booleanConverter);
        claimTypeConverters.put(StandardClaimNames.PHONE_NUMBER_VERIFIED, booleanConverter);
        claimTypeConverters.put(StandardClaimNames.UPDATED_AT, instantConverter);
        return claimTypeConverters;
    }

    private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
        final TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
        return source -> ClaimConversionService.getSharedInstance().convert(source, sourceDescriptor, targetDescriptor);
    }

    private boolean shouldRetrieveUserInfo() {
        LOG.info("User info always retrieving from user info endpoint");
        return true;
    }

}
