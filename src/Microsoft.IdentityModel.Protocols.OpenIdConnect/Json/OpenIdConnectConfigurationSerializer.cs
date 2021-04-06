// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if !NET45
using System;
using System.IO;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
 #pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class OpenIdConnectSerializer
    {
        public OpenIdConnectConfiguration Read(string json)
        {
            ReadOnlySpan<byte> bytes = UTF8Encoding.UTF8.GetBytes(json).AsSpan<byte>();
            Utf8JsonReader reader = new Utf8JsonReader(bytes);
            reader.Read();

            if (reader.TokenType != JsonTokenType.StartObject)
                throw new JsonException();

            OpenIdConnectConfiguration openIdConnectConfiguration = new OpenIdConnectConfiguration();

            do
            {
                if (JsonSerializerHelper.IsEndObject(ref reader, true))
                    break;

                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    string propertyName = JsonSerializerHelper.GetPropertyName(ref reader, this, true);

                    if (propertyName == SerializationConstants.AcrValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.AcrValuesSupported);

                    if (propertyName == SerializationConstants.AuthorizationEndpoint)
                        openIdConnectConfiguration.AuthorizationEndpoint = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.CheckSessionIframe)
                        openIdConnectConfiguration.CheckSessionIframe = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.ClaimsSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.ClaimsSupported);

                    if (propertyName == SerializationConstants.ClaimTypesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.ClaimTypesSupported);

                    if (propertyName == SerializationConstants.DisplayValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.DisplayValuesSupported);

                    if (propertyName == SerializationConstants.EndSessionEndpoint)
                        openIdConnectConfiguration.EndSessionEndpoint = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.FrontchannelLogoutSessionSupported)
                        openIdConnectConfiguration.FrontchannelLogoutSessionSupported = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.GrantTypesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.GrantTypesSupported);

                    if (propertyName == SerializationConstants.HttpLogoutSupported)
                        openIdConnectConfiguration.HttpLogoutSupported = JsonSerializerHelper.ReadBoolean(ref reader);

                    if (propertyName == SerializationConstants.IdTokenEncryptionAlgValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.IdTokenEncryptionAlgValuesSupported);

                    if (propertyName == SerializationConstants.IdTokenEncryptionEncValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.IdTokenEncryptionEncValuesSupported);

                    if (propertyName == SerializationConstants.IdTokenSigningAlgValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.IdTokenSigningAlgValuesSupported);

                    if (propertyName == SerializationConstants.IntrospectionEndpoint)
                        openIdConnectConfiguration.IntrospectionEndpoint = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.IntrospectionEndpointAuthSigningAlgValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.IntrospectionEndpointAuthSigningAlgValuesSupported);

                    if (propertyName == SerializationConstants.IntrospectionEndpointAuthMethodsSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.IntrospectionEndpointAuthMethodsSupported);

                    if (propertyName == SerializationConstants.Issuer)
                        openIdConnectConfiguration.Issuer = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.JwksUri)
                        openIdConnectConfiguration.JwksUri = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.OpPolicyUri)
                        openIdConnectConfiguration.OpPolicyUri = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.OpTosUri)
                        openIdConnectConfiguration.OpTosUri = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.RegistrationEndpoint)
                        openIdConnectConfiguration.RegistrationEndpoint = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.RequestObjectEncryptionAlgValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.RequestObjectEncryptionAlgValuesSupported);

                    if (propertyName == SerializationConstants.RequestObjectSigningAlgValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.RequestObjectSigningAlgValuesSupported);

                    if (propertyName == SerializationConstants.RequestParameterSupported)
                        openIdConnectConfiguration.RequestParameterSupported = JsonSerializerHelper.ReadBoolean(ref reader);

                    if (propertyName == SerializationConstants.RequireRequestUriRegistration)
                        openIdConnectConfiguration.RequireRequestUriRegistration = JsonSerializerHelper.ReadBoolean(ref reader);

                    if (propertyName == SerializationConstants.RequestUriParameterSupported)
                        openIdConnectConfiguration.RequestUriParameterSupported = JsonSerializerHelper.ReadBoolean(ref reader);

                    if (propertyName == SerializationConstants.ResponseModesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.ResponseModesSupported);

                    if (propertyName == SerializationConstants.ResponseTypesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.ResponseTypesSupported);

                    if (propertyName == SerializationConstants.RequestObjectEncryptionEncValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.RequestObjectEncryptionEncValuesSupported);

                    if (propertyName == SerializationConstants.ScopesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.ScopesSupported);

                    if (propertyName == SerializationConstants.ServiceDocumentation)
                        openIdConnectConfiguration.ServiceDocumentation = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.SubjectTypesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.SubjectTypesSupported);

                    if (propertyName == SerializationConstants.TokenEndpoint)
                        openIdConnectConfiguration.TokenEndpoint = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.TokenEndpointAuthSigningAlgValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.TokenEndpointAuthSigningAlgValuesSupported);

                    if (propertyName == SerializationConstants.UILocalesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.UILocalesSupported);

                    if (propertyName == SerializationConstants.UserInfoEndpoint)
                        openIdConnectConfiguration.UserInfoEndpoint = JsonSerializerHelper.ReadString(ref reader);

                    if (propertyName == SerializationConstants.UserInfoEndpointEncryptionAlgValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.UserInfoEndpointEncryptionAlgValuesSupported);

                    if (propertyName == SerializationConstants.UserInfoEndpointEncryptionEncValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.UserInfoEndpointEncryptionEncValuesSupported);

                    if (propertyName == SerializationConstants.UserInfoEndpointSigningAlgValuesSupported)
                        JsonSerializerHelper.ReadStrings(ref reader, openIdConnectConfiguration.UserInfoEndpointSigningAlgValuesSupported);

                    else
                        openIdConnectConfiguration.AdditionalData[propertyName] = ReadUnknownProperty(ref reader);
                }
            } while (reader.Read());

            return openIdConnectConfiguration;
        }

        protected static object ReadUnknownProperty(ref Utf8JsonReader reader)
        {
            if (reader.TokenType == JsonTokenType.String)
                return reader.GetString();
            else if (reader.TokenType == JsonTokenType.Number)
                return reader.GetInt64();
            else if (reader.TokenType == JsonTokenType.False)
                return reader.GetBoolean();
            else if (reader.TokenType == JsonTokenType.True)
                return reader.GetBoolean();

            //else if (reader.TokenType == JsonTokenType.StartObject)
            //    reader.Skip();
            //else if (reader.TokenType == JsonTokenType.Null)
            //    reader.Skip();
            //else if (reader.TokenType == JsonTokenType.StartArray)
            //    return ReadJsonArray(reader);

            reader.Skip();
            return null;
        }

        public static string Write(OpenIdConnectConfiguration openIdConnectConfiguration)
        {
            _ = openIdConnectConfiguration ?? throw new ArgumentNullException(nameof(openIdConnectConfiguration));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                Utf8JsonWriter writer = JsonSerializerHelper.GetUtf8JsonWriter(memoryStream);
                try
                {
                    writer.WriteStartObject();

                    if (openIdConnectConfiguration.AcrValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.AcrValuesSupported, openIdConnectConfiguration.AcrValuesSupported);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.AuthorizationEndpoint))
                        writer.WriteString(SerializationConstants.AuthorizationEndpoint, openIdConnectConfiguration.AuthorizationEndpoint);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.CheckSessionIframe))
                        writer.WriteString(SerializationConstants.CheckSessionIframe, openIdConnectConfiguration.CheckSessionIframe);

                    if (openIdConnectConfiguration.ClaimsSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.ClaimsSupported, openIdConnectConfiguration.ClaimsSupported);

                    if (openIdConnectConfiguration.ClaimsLocalesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.ClaimsLocalesSupported, openIdConnectConfiguration.ClaimsLocalesSupported);

                    writer.WriteBoolean(SerializationConstants.ClaimsParameterSupported, openIdConnectConfiguration.ClaimsParameterSupported);

                    if (openIdConnectConfiguration.ClaimTypesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.ClaimTypesSupported, openIdConnectConfiguration.ClaimTypesSupported);

                    if (openIdConnectConfiguration.DisplayValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.DisplayValuesSupported, openIdConnectConfiguration.DisplayValuesSupported);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.EndSessionEndpoint))
                        writer.WriteString(SerializationConstants.EndSessionEndpoint, openIdConnectConfiguration.EndSessionEndpoint);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.FrontchannelLogoutSessionSupported))
                        writer.WriteString(SerializationConstants.FrontchannelLogoutSessionSupported, openIdConnectConfiguration.FrontchannelLogoutSessionSupported);

                    // TODO - brentsch, FrontchannelLogoutSupported should be a boolean that is a bug in Wilson
                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.FrontchannelLogoutSupported))
                        writer.WriteString(SerializationConstants.FrontchannelLogoutSupported, openIdConnectConfiguration.FrontchannelLogoutSupported);

                    if (openIdConnectConfiguration.GrantTypesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.GrantTypesSupported, openIdConnectConfiguration.GrantTypesSupported);

                    writer.WriteBoolean(SerializationConstants.HttpLogoutSupported, openIdConnectConfiguration.HttpLogoutSupported);

                    if (openIdConnectConfiguration.IdTokenEncryptionAlgValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.IdTokenEncryptionAlgValuesSupported, openIdConnectConfiguration.IdTokenEncryptionAlgValuesSupported);

                    if (openIdConnectConfiguration.IdTokenEncryptionEncValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.IdTokenEncryptionEncValuesSupported, openIdConnectConfiguration.IdTokenEncryptionEncValuesSupported);

                    if (openIdConnectConfiguration.IdTokenSigningAlgValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.IdTokenSigningAlgValuesSupported, openIdConnectConfiguration.IdTokenSigningAlgValuesSupported);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.IntrospectionEndpoint))
                        writer.WriteString(SerializationConstants.IntrospectionEndpoint, openIdConnectConfiguration.IntrospectionEndpoint);

                    if (openIdConnectConfiguration.IntrospectionEndpointAuthSigningAlgValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.IntrospectionEndpointAuthSigningAlgValuesSupported, openIdConnectConfiguration.IntrospectionEndpointAuthSigningAlgValuesSupported);

                    if (openIdConnectConfiguration.IntrospectionEndpointAuthMethodsSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.IntrospectionEndpointAuthMethodsSupported, openIdConnectConfiguration.IntrospectionEndpointAuthMethodsSupported);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.Issuer))
                        writer.WriteString(SerializationConstants.Issuer, openIdConnectConfiguration.Issuer);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.JwksUri))
                        writer.WriteString(SerializationConstants.JwksUri, openIdConnectConfiguration.JwksUri);

                    writer.WriteBoolean(SerializationConstants.LogoutSessionSupported, openIdConnectConfiguration.LogoutSessionSupported);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.OpPolicyUri))
                        writer.WriteString(SerializationConstants.OpPolicyUri, openIdConnectConfiguration.OpPolicyUri);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.OpTosUri))
                        writer.WriteString(SerializationConstants.OpTosUri, openIdConnectConfiguration.OpTosUri);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.RegistrationEndpoint))
                        writer.WriteString(SerializationConstants.RegistrationEndpoint, openIdConnectConfiguration.RegistrationEndpoint);

                    if (openIdConnectConfiguration.RequestObjectEncryptionAlgValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.RequestObjectEncryptionAlgValuesSupported, openIdConnectConfiguration.RequestObjectEncryptionAlgValuesSupported);

                    if (openIdConnectConfiguration.RequestObjectSigningAlgValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.RequestObjectSigningAlgValuesSupported, openIdConnectConfiguration.RequestObjectSigningAlgValuesSupported);

                    writer.WriteBoolean(SerializationConstants.RequestParameterSupported, openIdConnectConfiguration.RequestParameterSupported);

                    writer.WriteBoolean(SerializationConstants.RequireRequestUriRegistration, openIdConnectConfiguration.RequireRequestUriRegistration);

                    writer.WriteBoolean(SerializationConstants.RequestUriParameterSupported, openIdConnectConfiguration.RequestUriParameterSupported);

                    if (openIdConnectConfiguration.ResponseModesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.ResponseModesSupported, openIdConnectConfiguration.ResponseModesSupported);

                    if (openIdConnectConfiguration.ResponseTypesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.ResponseTypesSupported, openIdConnectConfiguration.ResponseTypesSupported);

                    if (openIdConnectConfiguration.RequestObjectEncryptionEncValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.RequestObjectEncryptionEncValuesSupported, openIdConnectConfiguration.RequestObjectEncryptionEncValuesSupported);

                    if (openIdConnectConfiguration.ScopesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.ScopesSupported, openIdConnectConfiguration.ScopesSupported);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.ServiceDocumentation))
                        writer.WriteString(SerializationConstants.ServiceDocumentation, openIdConnectConfiguration.ServiceDocumentation);

                    if (openIdConnectConfiguration.SubjectTypesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.SubjectTypesSupported, openIdConnectConfiguration.SubjectTypesSupported);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.TokenEndpoint))
                        writer.WriteString(SerializationConstants.TokenEndpoint, openIdConnectConfiguration.TokenEndpoint);

                    if (openIdConnectConfiguration.TokenEndpointAuthSigningAlgValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.TokenEndpointAuthSigningAlgValuesSupported, openIdConnectConfiguration.TokenEndpointAuthSigningAlgValuesSupported);

                    if (openIdConnectConfiguration.UILocalesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.UILocalesSupported, openIdConnectConfiguration.UILocalesSupported);

                    if (!string.IsNullOrEmpty(openIdConnectConfiguration.UserInfoEndpoint))
                        writer.WriteString(SerializationConstants.UserInfoEndpoint, openIdConnectConfiguration.UserInfoEndpoint);

                    if (openIdConnectConfiguration.UserInfoEndpointEncryptionAlgValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.UserInfoEndpointEncryptionAlgValuesSupported, openIdConnectConfiguration.UserInfoEndpointEncryptionAlgValuesSupported);

                    if (openIdConnectConfiguration.UserInfoEndpointEncryptionEncValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.UserInfoEndpointEncryptionEncValuesSupported, openIdConnectConfiguration.UserInfoEndpointEncryptionEncValuesSupported);

                    if (openIdConnectConfiguration.UserInfoEndpointSigningAlgValuesSupported.Count > 0)
                        JsonSerializerHelper.WriteStrings(ref writer, SerializationConstants.UserInfoEndpointSigningAlgValuesSupported, openIdConnectConfiguration.UserInfoEndpointSigningAlgValuesSupported);

                    writer.WriteEndObject();
                    writer.Flush();
                }
                finally
                {
                    writer.Dispose();
                }

                return UTF8Encoding.UTF8.GetString(memoryStream.ToArray());
            }
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
#endif // !NET45
