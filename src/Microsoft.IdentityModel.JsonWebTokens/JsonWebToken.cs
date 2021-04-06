//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
#if !NET45
using System.Text.Json;
#endif
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a JSON Web Token (JWT). 
    /// </summary>
    public class JsonWebToken : SecurityToken
    {
        internal JsonClaimSet PayloadClaimSet;
        internal JsonClaimSet HeaderClaimSet;

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/><see cref="Claim"/> for each JSON { name, value }.
        /// </summary>
        public virtual IEnumerable<Claim> Claims
        {
            get
            {
                if (InnerToken != null)
                    return InnerToken.Claims;

                return PayloadClaimSet.Claims(Issuer ?? ClaimsIdentity.DefaultIssuer);

            }
        }

        internal bool HasSignature { get; set; }

        internal byte[] _hBytes;
        internal byte[] _hpUtf8Bytes;
        internal char[] _pBytes;
        internal byte[] _sBytes;

        private Lazy<string> _act;
        private Lazy<string> _alg;
        private Lazy<IEnumerable<string>> _audiences;
        private Lazy<string> _cty;
        private Lazy<string> _enc;
        private Lazy<string> _encodedPayload;
        private Lazy<DateTime> _iat;
        private Lazy<string> _id;
        private Lazy<string> _iss;
        private Lazy<string> _kid;
        private Lazy<string> _sub;
        private Lazy<string> _typ;
        private Lazy<DateTime> _validFrom;
        private Lazy<DateTime> _validTo;
        private Lazy<string> _x5t;
        private Lazy<string> _zip;
        internal byte[] _ciphertextBytes;
        internal byte[] _initializationVectorBytes;
        internal byte[] _authenticationTagBytes;
        internal byte[] _encodedHeaderAsciiBytes;
        internal byte[] _encryptedKeyBytes;

        /// <summary>
        /// Initializes a new instance of <see cref="JsonWebToken"/> from a string in JWS or JWE Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A JSON Web Token that has been serialized in JWS or JWE Compact serialized format.</param>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null or empty.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' is not in JWS or JWE Compact serialization format.</exception>
        /// <remarks>
        /// The contents of the returned <see cref="JsonWebToken"/> have not been validated, the JSON Web Token is simply decoded. Validation can be accomplished using the validation methods in <see cref="JsonWebTokenHandler"/>
        /// </remarks>
        public JsonWebToken(string jwtEncodedString)
        {
            if (string.IsNullOrEmpty(jwtEncodedString))
                throw new ArgumentNullException(nameof(jwtEncodedString));

            Initialize();
            ReadToken(jwtEncodedString);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonWebToken"/> class where the header contains the crypto algorithms applied to the encoded header and payload.
        /// </summary>
        /// <param name="header">A string containing JSON which represents the cryptographic operations applied to the JWT and optionally any additional properties of the JWT.</param>
        /// <param name="payload">A string containing JSON which represents the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }.</param>
        /// <exception cref="ArgumentNullException">'header' is null.</exception>
        /// <exception cref="ArgumentNullException">'payload' is null.</exception>
        public JsonWebToken(string header, string payload)
        {
            if (string.IsNullOrEmpty(header))
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            try
            {
                HeaderClaimSet = new JsonClaimSet(header);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14301, header), ex));
            }

            try
            {
                PayloadClaimSet = new JsonClaimSet(payload);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14302, payload), ex));
            }

            Initialize();
        }

        private void Initialize()
        {
            _act = new Lazy<string>(ActorFactory);
            _alg = new Lazy<string>(AlgFactory);
            _audiences = new Lazy<IEnumerable<string>>(AudiencesFactory);
            _cty = new Lazy<string>(CtyFactory);
            _enc = new Lazy<string>(EncFactory);
            _encodedPayload = new Lazy<string>(EncodedPayloadFactory);
            _iat = new Lazy<DateTime>(IatFactory);
            _id = new Lazy<string>(IdFactory);
            _iss = new Lazy<string>(IssuerFactory);
            _kid = new Lazy<string>(KidFactory);
            _sub = new Lazy<string>(SubFactory);
            _typ = new Lazy<string>(TypFactory);
            _validTo = new Lazy<DateTime>(ValidToFactory);
            _validFrom = new Lazy<DateTime>(ValidFromFactory);
            _x5t = new Lazy<string>(X5tFactory);
            _zip = new Lazy<string>(ZipFactory);
        }

        /// <summary>
        /// Gets the 'value' of the 'actort' claim { actort, 'value' }.
        /// </summary>
        /// <remarks>If the 'actort' claim is not found, an empty string is returned.</remarks> 
        public string Actor => _act.Value;

        internal string ActorFactory()
        {
            return (InnerToken == null) ? PayloadClaimSet.GetStringValue(JwtRegisteredClaimNames.Actort) : InnerToken.PayloadClaimSet.GetStringValue(JwtRegisteredClaimNames.Actort);
        }

        /// <summary>
        /// Gets the 'value' of the 'alg' claim { alg, 'value' }.
        /// </summary>
        /// <remarks>If the 'alg' claim is not found, an empty string is returned.</remarks>   
        public string Alg => _alg.Value;

        private string AlgFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Alg);
        }

        /// <summary>
        /// Gets the list of 'aud' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'aud' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences => _audiences.Value;

        private IEnumerable<string> AudiencesFactory()
        {
#if NET45
            if (PayloadClaimSet.TryGetValue(JwtRegisteredClaimNames.Aud, out JToken value))
            {
                if (value.Type is JTokenType.String)
                    return new List<string> { value.ToObject<string>() };
                else if (value.Type is JTokenType.Array)
                    return value.ToObject<List<string>>();
            }
#else
            if (PayloadClaimSet.TryGetValue(JwtRegisteredClaimNames.Aud, out JsonElement audiences))
            {
                if (audiences.ValueKind == JsonValueKind.String)
                    return new List<string> { audiences.GetString() };

                if (audiences.ValueKind == JsonValueKind.Array)
                {
                    List<string> retVal = new List<string>();
                    foreach (JsonElement jsonElement in audiences.EnumerateArray())
                        retVal.Add(jsonElement.ToString());

                    return retVal;
                }
            }
#endif
            return Enumerable.Empty<string>();
        }

        /// <summary>
        /// Gets the AuthenticationTag from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string AuthenticationTag { get; internal set; }

        /// <summary>
        /// Gets the Ciphertext from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string Ciphertext { get; internal set; }

        /// <summary>
        /// Gets the 'value' of the 'cty' claim { cty, 'value' }.
        /// </summary>
        /// <remarks>If the 'cty' claim is not found, an empty string is returned.</remarks>   
        public string Cty => _cty.Value;

        private string CtyFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Cty);
        }

        /// <summary>
        /// Gets the 'value' of the 'enc' claim { enc, 'value' }.
        /// </summary>
        /// <remarks>If the 'enc' value is not found, an empty string is returned.</remarks>   
        public string Enc => _enc.Value;

        private string EncFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Enc);
        }

        /// <summary>
        /// Gets the EncryptedKey from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string EncryptedKey { get; internal set; }

        /// <summary>
        /// Gets the EncodedPayload from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string EncodedPayload => _encodedPayload.Value;

        private string EncodedPayloadFactory()
        {
            return new string(_pBytes);
        }

        internal bool HasPayloadClaim(string claimName)
        {
            return PayloadClaimSet.HasClaim(claimName);
        }

        /// <summary>
        /// Gets the 'value' of the 'jti' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'jti' claim is not found, an empty string is returned.</remarks>
        public override string Id => _id.Value;

        private string IdFactory()
        {
            return PayloadClaimSet.GetStringValue(JwtRegisteredClaimNames.Jti);
        }

        /// <summary>
        /// Gets the InitializationVector from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string InitializationVector { get; internal set; }

        /// <summary>
        /// Gets the <see cref="JsonWebToken"/> associated with this instance.
        /// </summary>
        public JsonWebToken InnerToken { get; internal set; }

        /// <summary>
        /// Gets the 'value' of the 'iat' claim { iat, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'iat' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime IssuedAt => _iat.Value;

        private DateTime IatFactory()
        {
            return PayloadClaimSet.GetDateTime(JwtRegisteredClaimNames.Iat);
        }

        /// <summary>
        /// Gets the 'value' of the 'iss' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'iss' claim is not found, an empty string is returned.</remarks>   
        public override string Issuer => _iss.Value;

        internal string IssuerFactory()
        {
            return PayloadClaimSet.GetStringValue(JwtRegisteredClaimNames.Iss);
        }

        /// <summary>
        /// Gets the 'value' of the 'kid' claim { kid, 'value' }.
        /// </summary>
        /// <remarks>If the 'kid' claim is not found, an empty string is returned.</remarks>   
        public string Kid => _kid.Value;

        private string KidFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Kid);
        }

        /// <summary>
        /// Gets the EncodedHeader from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string EncodedHeader { get; internal set; }

        /// <summary>
        /// Gets the EncodedSignature from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string EncodedSignature { get; internal set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        public string EncodedToken { get; private set; }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override SecurityKey SecurityKey { get; }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that was used to sign this token.
        /// </summary>
        public override SecurityKey SigningKey { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'sub' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'sub' claim is not found, an empty string is returned.</remarks>   
        public string Subject => _sub.Value;

        private string SubFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtRegisteredClaimNames.Sub);
        }

        /// <summary>
        /// Gets the 'value' of the 'typ' claim { typ, 'value' }.
        /// </summary>
        /// <remarks>If the 'typ' claim is not found, an empty string is returned.</remarks>   
        public string Typ => _typ.Value;

        private string TypFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Typ);
        }

        /// <summary>
        /// Gets the 'value' of the 'kid' claim { kid, 'value' }.
        /// </summary>
        /// <remarks>If the 'kid' claim is not found, an empty string is returned.</remarks>   
        public string X5t => _x5t.Value;

        private string X5tFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.X5t);
        }

        /// <summary>
        /// Gets the 'value' of the 'nbf' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'nbf' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidFrom => _validFrom.Value;

        internal DateTime ValidFromFactory()
        {
            return PayloadClaimSet.GetDateTime(JwtRegisteredClaimNames.Nbf);
        }

        /// <summary>
        /// Gets the 'value' of the 'exp' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'exp' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidTo => _validTo.Value;

        internal DateTime ValidToFactory()
        {
            return PayloadClaimSet.GetDateTime(JwtRegisteredClaimNames.Exp);
        }

        /// <summary>
        /// Gets the 'value' of the 'zip' claim { zip, 'value' }.
        /// </summary>
        /// <remarks>If the 'zip' claim is not found, an empty string is returned.</remarks>   
        public string Zip => _zip.Value;

        private string ZipFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Zip);
        }

        /// <summary>
        /// Gets a <see cref="Claim"/> representing the { key, 'value' } pair corresponding to the provided <paramref name="key"/>.
        /// </summary>
        /// <remarks>If the key has no corresponding value, this method will throw.</remarks>   
        public Claim GetClaim(string key)
        {
            return PayloadClaimSet.GetClaim(key, Issuer ?? ClaimsIdentity.DefaultIssuer);
        }

        /// <summary>
        /// Gets the 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        /// <remarks>If the key has no corresponding value, this method will throw. </remarks>   
        public T GetPayloadValue<T>(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (typeof(T).Equals(typeof(Claim)))
                return (T)(object)GetClaim(key);

            return PayloadClaimSet.GetValue<T>(key);
        }

        internal int NumberOfSegments { get; private set; }

        private void ReadToken(string encodedJson)
        {
            List<int> dots = new List<int>();
            int index = 0;
            while (index < encodedJson.Length && dots.Count <= JwtConstants.MaxJwtSegmentCount + 1)
            {
                if (encodedJson[index] == '.')
                    dots.Add(index);

                index++;
            }

            EncodedToken = encodedJson;
            if (dots.Count == JwtConstants.JwsSegmentCount - 1)
            {
                if (dots[1] + 1 == encodedJson.Length)
                {
                    HasSignature = false;
                    // TODO - have fixed value for this.
                    _sBytes = Base64UrlEncoder.UnsafeDecode(string.Empty.ToCharArray());
                }
                else
                {
                    HasSignature = true;
                    _sBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[1] + 1, encodedJson.Length - dots[1] - 1));
                }

                _pBytes = encodedJson.ToCharArray(dots[0] + 1, dots[1] - dots[0] - 1);
                _hpUtf8Bytes = Encoding.UTF8.GetBytes(encodedJson.ToCharArray(0, dots[1]));
                try
                {
                    HeaderClaimSet = new JsonClaimSet(Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(0, dots[0])));
                }
                catch(Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14102, encodedJson.Substring(0, dots[0]), encodedJson), ex));
                }

                try
                {
                    PayloadClaimSet = new JsonClaimSet(Base64UrlEncoder.UnsafeDecode(_pBytes));
                }
                catch(Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14101, encodedJson.Substring(dots[0], dots[1] - dots[0]), encodedJson), ex));
                }
            }
            else if (dots.Count == JwtConstants.JweSegmentCount - 1)
            {
                char[] encodedHeader = encodedJson.ToCharArray(0, dots[0]);
                _encodedHeaderAsciiBytes = Encoding.ASCII.GetBytes(encodedHeader);
                _encryptedKeyBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[0] + 1, dots[1] - dots[0] - 1));
                _initializationVectorBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[1] + 1, dots[2] - dots[1] - 1));
                _ciphertextBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[2] + 1, dots[3] - dots[2] - 1));
                if (_ciphertextBytes.Length == 0)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX14306));

                _authenticationTagBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[3] + 1, encodedJson.Length - dots[3] - 1));
                try
                {
                    HeaderClaimSet = new JsonClaimSet(Base64UrlEncoder.UnsafeDecode(encodedHeader));
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14102, encodedJson.Substring(0, dots[0]), encodedJson), ex));
                }
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14100, encodedJson)));
            }

            NumberOfSegments = dots.Count;
        }

        /// <summary>
        /// Tries to get the <see cref="Claim"/> representing the { key, 'value' } pair corresponding to the provided <paramref name="key"/>.
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns false. Otherwise returns true. </remarks>   
        public bool TryGetClaim(string key, out Claim value)
        {
            return PayloadClaimSet.TryGetClaim(key, Issuer ?? ClaimsIdentity.DefaultIssuer, out value);
        }

        /// <summary>
        /// Tries to get the 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns false. Otherwise returns true. </remarks>   
        public bool TryGetPayloadValue<T>(string key, out T value)
        {
            if (string.IsNullOrEmpty(key))
            {
                value = default(T);
                return false;
            }

            if (typeof(T).Equals(typeof(Claim)))
            {
                var foundClaim = TryGetClaim(key, out var claim);
                value = (T)(object)claim;
                return foundClaim;
            }

            return PayloadClaimSet.TryGetValue<T>(key, out value);
        }

        /// <summary>
        /// Gets the 'value' corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        /// <remarks>If the key has no corresponding value, this method will throw. </remarks>   
        public T GetHeaderValue<T>(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw LogHelper.LogArgumentNullException(nameof(key));

            return HeaderClaimSet.GetValue<T>(key);
        }

        /// <summary>
        /// Tries to get the value corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns false. Otherwise returns true. </remarks>   
        public bool TryGetHeaderValue<T>(string key, out T value)
        {
            if (string.IsNullOrEmpty(key))
            {
                value = default;
                return false;
            }

            return HeaderClaimSet.TryGetValue<T>(key, out value);
        }
    }
}
