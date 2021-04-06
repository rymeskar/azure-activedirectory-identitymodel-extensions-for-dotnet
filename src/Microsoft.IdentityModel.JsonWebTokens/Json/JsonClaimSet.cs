// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Text;

#if NET45
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
#else
using System.Text.Json;
#endif

namespace Microsoft.IdentityModel.JsonWebTokens
{
    internal class JsonClaimSet
    {
        IList<Claim> _claims;

#if !NET45
        private static Type _typeofDateTime = typeof(DateTime);
#endif
        public JsonClaimSet()
        {
#if NET45
            RootElement = new JObject();
#else
            RootElement = new JsonElement();
#endif
        }

        public JsonClaimSet(byte[] jsonBytes)
        {
#if NET45
            RootElement = JObject.Parse(Encoding.UTF8.GetString(jsonBytes));
#else
            RootElement = JsonDocument.Parse(jsonBytes).RootElement;
#endif
        }

        public JsonClaimSet(string json)
        {
#if NET45
            RootElement = JObject.Parse(json);
#else
            RootElement = JsonDocument.Parse(json).RootElement;
#endif
        }

#if NET45
        public bool TryGetValue(string claimName, out JToken json)
        {
            return RootElement.TryGetValue(claimName, out json);
        }

        public JObject RootElement { get; }
#else
        public bool TryGetValue(string claimName, out JsonElement json)
        {
            return RootElement.TryGetProperty(claimName, out json);
        }

        public JsonElement RootElement { get; }
#endif
        internal IList<Claim> Claims(string issuer)
        {
            if (_claims != null)
                return _claims;

            _claims = new List<Claim>();
#if NET45
            if (!RootElement.HasValues)
                return _claims;

            // there is some code redundancy here that was not factored as this is a high use method. Each identity received from the host will pass through here.
            foreach (var entry in RootElement)
            {
                if (entry.Value == null)
                {
                    _claims.Add(new Claim(entry.Key, string.Empty, JsonClaimValueTypes.JsonNull, issuer, issuer));
                    continue;
                }

                if (entry.Value.Type is JTokenType.String)
                {
                    var claimValue = entry.Value.ToObject<string>();
                    _claims.Add(new Claim(entry.Key, claimValue, ClaimValueTypes.String, issuer, issuer));
                    continue;
                }

                var jtoken = entry.Value;
                if (jtoken != null)
                {
                    AddClaimsFromJToken(_claims, entry.Key, jtoken, issuer);
                    continue;
                }
            }

            return _claims;
#else
            foreach (JsonProperty payloadObject in RootElement.EnumerateObject())
            {
                // Json.net recognized DateTime.
                if (payloadObject.Value.ValueKind == JsonValueKind.String)
                {
                    if (payloadObject.Value.TryGetDateTime(out DateTime dateTime))
                        _claims.Add(new Claim(payloadObject.Name, payloadObject.Value.GetString(), ClaimValueTypes.DateTime, issuer, issuer));
                    else
                        _claims.Add(new Claim(payloadObject.Name, payloadObject.Value.GetString(), ClaimValueTypes.String, issuer, issuer));
                }
                else if (payloadObject.Value.ValueKind == JsonValueKind.Null)
                    _claims.Add(new Claim(payloadObject.Name, string.Empty, JsonClaimValueTypes.JsonNull, issuer, issuer));
                else if (payloadObject.Value.ValueKind == JsonValueKind.Object)
                    _claims.Add(new Claim(payloadObject.Name, payloadObject.Value.ToString(), JsonClaimValueTypes.Json, issuer, issuer));
                else if (payloadObject.Value.ValueKind == JsonValueKind.False)
                    _claims.Add(new Claim(payloadObject.Name, "false", ClaimValueTypes.Boolean, issuer, issuer));
                else if (payloadObject.Value.ValueKind == JsonValueKind.True)
                    _claims.Add(new Claim(payloadObject.Name, "true", ClaimValueTypes.Boolean, issuer, issuer));
                else if (payloadObject.Value.ValueKind == JsonValueKind.Number)
                {
                    if (payloadObject.Value.TryGetInt64(out long _))
                        _claims.Add(new Claim(payloadObject.Name, payloadObject.Value.ToString(), ClaimValueTypes.Integer64, issuer, issuer));
                    else if (payloadObject.Value.TryGetInt32(out int _))
                        _claims.Add(new Claim(payloadObject.Name, payloadObject.Value.ToString(), ClaimValueTypes.Integer32, issuer, issuer));
                    else if (payloadObject.Value.TryGetDouble(out double _))
                        _claims.Add(new Claim(payloadObject.Name, payloadObject.Value.ToString(), ClaimValueTypes.Double, issuer, issuer));
                    else if (payloadObject.Value.TryGetDecimal(out decimal _))
                        _claims.Add(new Claim(payloadObject.Name, payloadObject.Value.ToString(), ClaimValueTypes.Double, issuer, issuer));
                    else if (payloadObject.Value.TryGetUInt64(out ulong _))
                        _claims.Add(new Claim(payloadObject.Name, payloadObject.Value.ToString(), ClaimValueTypes.UInteger64, issuer, issuer));
                    else if (payloadObject.Value.TryGetUInt32(out uint _))
                        _claims.Add(new Claim(payloadObject.Name, payloadObject.Value.ToString(), ClaimValueTypes.UInteger32, issuer, issuer));
                }
                else if (payloadObject.Value.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement jsonElement in payloadObject.Value.EnumerateArray())
                    {
                        if (jsonElement.ValueKind == JsonValueKind.Object)
                            _claims.Add(new Claim(payloadObject.Name, jsonElement.ToString(), JsonClaimValueTypes.Json, issuer, issuer));
                        else if (jsonElement.ValueKind == JsonValueKind.Array)
                            _claims.Add(new Claim(payloadObject.Name, jsonElement.ToString(), JsonClaimValueTypes.JsonArray, issuer, issuer));
                        else if (payloadObject.Value.ValueKind == JsonValueKind.String)
                            _claims.Add(new Claim(payloadObject.Name, jsonElement.GetString(), ClaimValueTypes.String, issuer, issuer));
                    }
                }
            }

        return _claims;
#endif
        }
#if NET45
        private static Claim CreateClaimFromJToken(string key, string issuer, JToken jToken)
        {
            if (jToken.Type == JTokenType.Null)
                return new Claim(key, string.Empty, JsonClaimValueTypes.JsonNull, issuer, issuer);
            else if (jToken.Type is JTokenType.Object)
                return new Claim(key, jToken.ToString(Formatting.None), JsonClaimValueTypes.Json, issuer, issuer);
            else if (jToken.Type is JTokenType.Array)
                return new Claim(key, jToken.ToString(Formatting.None), JsonClaimValueTypes.JsonArray, issuer, issuer);
            else if (jToken is JValue jvalue)
            {
                // String is special because item.ToString(Formatting.None) will result in "/"string/"". The quotes will be added.
                // Boolean needs item.ToString otherwise 'true' => 'True'
                if (jvalue.Type is JTokenType.String)
                    return new Claim(key, jvalue.Value.ToString(), ClaimValueTypes.String, issuer, issuer);
                // DateTime claims require special processing. jTokenValue.ToString(Formatting.None) will result in "\"dateTimeValue\"". The quotes will be added.
                else if (jvalue.Value is DateTime dateTimeValue)
                    return new Claim(key, dateTimeValue.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture), ClaimValueTypes.DateTime, issuer);
                else
                    return new Claim(key, jToken.ToString(Formatting.None), GetClaimValueType(jvalue.Value), issuer, issuer);
            }
            else
                return new Claim(key, jToken.ToString(Formatting.None), GetClaimValueType(jToken), issuer, issuer);
        }

        private static void AddClaimsFromJToken(IList<Claim> claims, string claimType, JToken jtoken, string issuer)
        {
            if (jtoken.Type is JTokenType.Object)
            {
                claims.Add(new Claim(claimType, jtoken.ToString(Formatting.None), JsonClaimValueTypes.Json, issuer, issuer));
            }
            else if (jtoken.Type is JTokenType.Array)
            {
                var jarray = jtoken as JArray;
                foreach (var item in jarray)
                {
                    switch (item.Type)
                    {
                        case JTokenType.Object:
                            claims.Add(new Claim(claimType, item.ToString(Formatting.None), JsonClaimValueTypes.Json, issuer, issuer));
                            break;

                        // only go one level deep on arrays.
                        case JTokenType.Array:
                            claims.Add(new Claim(claimType, item.ToString(Formatting.None), JsonClaimValueTypes.JsonArray, issuer, issuer));
                            break;

                        default:
                            AddDefaultClaimFromJToken(claims, claimType, item, issuer);
                            break;
                    }
                }
            }
            else
            {
                AddDefaultClaimFromJToken(claims, claimType, jtoken, issuer);
            }
        }

        private static void AddDefaultClaimFromJToken(IList<Claim> claims, string claimType, JToken jtoken, string issuer)
        {
            if (jtoken is JValue jvalue)
            {
                // String is special because item.ToString(Formatting.None) will result in "/"string/"". The quotes will be added.
                // Boolean needs item.ToString otherwise 'true' => 'True'
                if (jvalue.Type is JTokenType.String)
                    claims.Add(new Claim(claimType, jvalue.Value.ToString(), ClaimValueTypes.String, issuer, issuer));
                // DateTime claims require special processing. jtoken.ToString(Formatting.None) will result in "\"dateTimeValue\"". The quotes will be added.
                else if (jvalue.Value is DateTime dateTimeValue)
                    claims.Add(new Claim(claimType, dateTimeValue.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture), ClaimValueTypes.DateTime, issuer, issuer));
                else
                    claims.Add(new Claim(claimType, jtoken.ToString(Formatting.None), JsonClaimSet.GetClaimValueType(jvalue.Value), issuer, issuer));
            }
            else
                claims.Add(new Claim(claimType, jtoken.ToString(Formatting.None), JsonClaimSet.GetClaimValueType(jtoken), issuer, issuer));
        }
#endif
        internal bool TryGetClaim(string key, string issuer, out Claim claim)
        {
#if NET45
            if (!RootElement.TryGetValue(key, out var jTokenValue))
            {
                claim = null;
                return false;
            }

            claim = CreateClaimFromJToken(key, issuer, jTokenValue);
            return true;
#else
            if (!RootElement.TryGetProperty(key, out JsonElement jsonElement))
            {
                claim = null;
                return false;
            }

            claim = CreateClaimFromJsonElement(key, issuer, jsonElement);
            return true;
#endif
        }

#if !NET45
        private static Claim CreateClaimFromJsonElement(string key, string issuer, JsonElement jsonElement)
        {
            // Json.net recognized DateTime by default.
            if (jsonElement.ValueKind == JsonValueKind.String)
            {
                if (jsonElement.TryGetDateTime(out DateTime _))
                    return new Claim(key, jsonElement.GetString(), ClaimValueTypes.DateTime, issuer, issuer);
                else
                    return new Claim(key, jsonElement.GetString(), ClaimValueTypes.String, issuer, issuer);
            }
            else if (jsonElement.ValueKind == JsonValueKind.Null)
                return new Claim(key, string.Empty, JsonClaimValueTypes.JsonNull, issuer, issuer);
            else if (jsonElement.ValueKind == JsonValueKind.Object)
                return new Claim(key, jsonElement.ToString(), JsonClaimValueTypes.Json, issuer, issuer);
            else if (jsonElement.ValueKind == JsonValueKind.False)
                return new Claim(key, "false", ClaimValueTypes.Boolean, issuer, issuer);
            else if (jsonElement.ValueKind == JsonValueKind.True)
                return new Claim(key, "true", ClaimValueTypes.Boolean, issuer, issuer);
            else if (jsonElement.ValueKind == JsonValueKind.Number)
            {
                if (jsonElement.TryGetInt16(out short _))
                    return new Claim(key, jsonElement.ToString(), ClaimValueTypes.Integer, issuer, issuer);
                else if (jsonElement.TryGetInt32(out int _))
                    return new Claim(key, jsonElement.ToString(), ClaimValueTypes.Integer32, issuer, issuer);
                else if (jsonElement.TryGetInt64(out long _))
                    return new Claim(key, jsonElement.ToString(), ClaimValueTypes.Integer64, issuer, issuer);
                else if (jsonElement.TryGetDecimal(out decimal _))
                    return new Claim(key, jsonElement.ToString(), ClaimValueTypes.Double, issuer, issuer);
                else if (jsonElement.TryGetDouble(out double _))
                    return new Claim(key, jsonElement.ToString(), ClaimValueTypes.Double, issuer, issuer);
                else if (jsonElement.TryGetUInt32(out uint _))
                    return new Claim(key, jsonElement.ToString(), ClaimValueTypes.UInteger32, issuer, issuer);
                else if (jsonElement.TryGetUInt64(out ulong _))
                    return new Claim(key, jsonElement.ToString(), ClaimValueTypes.UInteger64, issuer, issuer);
            }
            else if (jsonElement.ValueKind == JsonValueKind.Array)
            {
                return new Claim(key, jsonElement.ToString(), JsonClaimValueTypes.JsonArray, issuer, issuer);
            }

            return null;
        }

        private static object CreateObjectFromJsonElement(JsonElement jsonElement)
        {
            if (jsonElement.ValueKind == JsonValueKind.Array)
            {
                int numberOfElements = 0;
                // is this an array of properties
                foreach(JsonElement element in jsonElement.EnumerateArray())
                    numberOfElements++;

                object[] objects = new object[numberOfElements];

                int index = 0;
                foreach (JsonElement element in jsonElement.EnumerateArray())
                    objects[index++] = CreateObjectFromJsonElement(element);

                return (object)objects;
            }
            else if (jsonElement.ValueKind == JsonValueKind.String)
            {
                if (DateTime.TryParse(jsonElement.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime dateTime))
                    return (object)dateTime;

                return jsonElement.GetString();
            }
            else if (jsonElement.ValueKind == JsonValueKind.Null)
                return (object)null;
            else if (jsonElement.ValueKind == JsonValueKind.Object)
                return jsonElement.ToString();
            else if (jsonElement.ValueKind == JsonValueKind.False)
                return (object)false;
            else if (jsonElement.ValueKind == JsonValueKind.True)
                return (object)true;
            else if (jsonElement.ValueKind == JsonValueKind.Number)
            {
                if (jsonElement.TryGetInt32(out int intValue))
                    return intValue;
                else if (jsonElement.TryGetInt64(out long longValue))
                    return longValue;
                else if (jsonElement.TryGetDecimal(out decimal decimalValue))
                    return decimalValue;
                else if (jsonElement.TryGetDouble(out double doubleValue))
                    return doubleValue;
                else if (jsonElement.TryGetUInt32(out uint uintValue))
                    return uintValue;
                else if (jsonElement.TryGetUInt64(out ulong ulongValue))
                    return ulongValue;
            }

            return jsonElement.GetString();
        }

        private static object CreateObjectFromJsonProperty(JsonProperty jsonProperty)
        {
            return jsonProperty.ToString();
        }
#endif
        internal Claim GetClaim(string key, string issuer)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

#if NET45
            if (!RootElement.TryGetValue(key, out var jTokenValue))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14304, key)));

            return CreateClaimFromJToken(key, issuer, jTokenValue);
#else
            if (!RootElement.TryGetProperty(key, out JsonElement jsonElement))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14304, key)));

            return CreateClaimFromJsonElement(key, issuer, jsonElement);
#endif
        }

        public static string GetClaimValueType(object obj)
        {
            if (obj == null)
                return JsonClaimValueTypes.JsonNull;

            var objType = obj.GetType();

            if (objType == typeof(string))
                return ClaimValueTypes.String;

            if (objType == typeof(int))
                return ClaimValueTypes.Integer;

            if (objType == typeof(bool))
                return ClaimValueTypes.Boolean;

            if (objType == typeof(double))
                return ClaimValueTypes.Double;

            if (objType == typeof(long))
            {
                long l = (long)obj;
                if (l >= int.MinValue && l <= int.MaxValue)
                    return ClaimValueTypes.Integer;

                return ClaimValueTypes.Integer64;
            }

            if (objType == typeof(DateTime))
                return ClaimValueTypes.DateTime;
#if NET45
            if (objType == typeof(JObject))
                return JsonClaimValueTypes.Json;

            if (objType == typeof(JArray))
                return JsonClaimValueTypes.JsonArray;
#endif
            return objType.ToString();
        }

        internal string GetStringValue(string key)
        {
#if NET45
            if (RootElement.TryGetValue(key, out JToken jtoken) && jtoken.Type == JTokenType.String)
                return (string)jtoken;
#else
            if (RootElement.TryGetProperty(key, out JsonElement jsonElement) && jsonElement.ValueKind == JsonValueKind.String)
                return jsonElement.GetString();
#endif
            return string.Empty;
        }

        internal DateTime GetDateTime(string key)
        {
#if NET45
            if (!RootElement.TryGetValue(key, out JToken jToken))
                return DateTime.MinValue;

            return EpochTime.DateTime(Convert.ToInt64(Math.Truncate(Convert.ToDouble(ParseTimeValue(key, jToken), CultureInfo.InvariantCulture))));
#else
            if (!RootElement.TryGetProperty(key, out JsonElement jsonElement))
                return DateTime.MinValue;

            return EpochTime.DateTime(Convert.ToInt64(Math.Truncate(Convert.ToDouble(ParseTimeValue(key, jsonElement), CultureInfo.InvariantCulture))));
#endif
        }

        public T GetValue<T>(string key)
        {
#if NET45
            if (!RootElement.TryGetValue(key, out var jTokenValue))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14304, key)));

            T value;
            if (jTokenValue.Type == JTokenType.Null)
            {
                if (Nullable.GetUnderlyingType(typeof(T)) != null)
                    value = (T)(object)null;
                else
                    value = default;
            }
            else
            {
                try
                {
                    value = jTokenValue.ToObject<T>();
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14305, key, typeof(T), jTokenValue.Type, jTokenValue.ToString()), ex));
                }
            }

            return value;
#else
            return GetValueInternal<T>(key, true, out bool _);
#endif
        }

#if !NET45
        private T GetValueInternal<T>(string key, bool throwEx, out bool found)
        {
            found = false;
            T value = default;
            if (!RootElement.TryGetProperty(key, out JsonElement jsonElement))
            {
                if (throwEx)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14304, key)));
                else
                    return value;
            }

            found = true;
            try
            {
                if (jsonElement.ValueKind == JsonValueKind.Null)
                {
                    if (Nullable.GetUnderlyingType(typeof(T)) != null)
                        value = (T)(object)null;
                    else
                        value = default;
                }
                else
                {
                    // need to adjust for object as value will be 
                    if (typeof(T) == typeof(object))
                    {
                        value = (T)CreateObjectFromJsonElement(jsonElement);
                    }
                    else if (typeof(T) == typeof(object[]))
                    {
                        if (jsonElement.ValueKind == JsonValueKind.Array)
                        {
                            int numberOfElements = 0;
                            // is this an array of properties
                            foreach (JsonElement element in jsonElement.EnumerateArray())
                                numberOfElements++;

                            object[] objects = new object[numberOfElements];

                            int index = 0;
                            foreach (JsonElement element in jsonElement.EnumerateArray())
                                objects[index++] = CreateObjectFromJsonElement(element);

                            return (T)(object)objects;
                        }
                        else
                        {
                            object[] objects = new object[1];
                            objects[0] = CreateObjectFromJsonElement(jsonElement);
                            return (T)(object)objects;
                        }
                    }
                    else if (jsonElement.ValueKind == JsonValueKind.String)
                    {
                        if (typeof(T) == _typeofDateTime && DateTime.TryParse(jsonElement.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime dateTime))
                            value = (T)(object)dateTime;
                        else
                            value = JsonSerializer.Deserialize<T>(jsonElement.GetRawText());
                    }
                    else if (typeof(T) == typeof(string))
                    {
                        value = (T)(jsonElement.ToString() as object);
                    }
                    else
                    {
                        value = JsonSerializer.Deserialize<T>(jsonElement.GetRawText());
                    }
                }
            }
            catch (Exception ex)
            {
                found = false;
                if (throwEx)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14305, key, typeof(T), jsonElement.ValueKind, jsonElement.GetRawText()), ex));
            }

            return value;
        }
#endif

        public bool TryGetValue<T>(string key, out T value)
        {
#if NET45
            if (RootElement.TryGetValue(key, out var jTokenValue))
            {
                try
                {
                    value = jTokenValue.ToObject<T>();
                    return true;
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    value = default(T);
                    return false;
                }
            }
            else
            {
                value = default;
            }

            return false;
#else
            value = GetValueInternal<T>(key, false, out bool found);
            return found;
#endif
        }

        internal bool HasClaim(string claimName)
        {
#if NET45
            return RootElement.TryGetValue(claimName, out _);
#else
            return RootElement.TryGetProperty(claimName, out _);
#endif
        }

#if NET45
        private static long ParseTimeValue(string claimName, JToken jToken)
        {
            if (jToken.Type == JTokenType.Integer || jToken.Type == JTokenType.Float)
            {
                return (long)jToken;
            }
            else if (jToken.Type == JTokenType.String)
            {
                if (long.TryParse((string)jToken, out long resultLong))
                    return resultLong;

                if (float.TryParse((string)jToken, out float resultFloat))
                    return (long)resultFloat;

                if (double.TryParse((string)jToken, out double resultDouble))
                    return (long)resultDouble;
            }

            throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX14300, claimName, jToken.ToString(), typeof(long))));
        }
#else
        private static long ParseTimeValue(string claimName, JsonElement jsonElement)
        {
            if (jsonElement.ValueKind == JsonValueKind.Number)
            {
                return jsonElement.GetInt64();
            }
            else if (jsonElement.ValueKind == JsonValueKind.String)
            {
                string str = jsonElement.GetString();
                if (long.TryParse(str, out long resultLong))
                    return resultLong;

                if (float.TryParse(str, out float resultFloat))
                    return (long)resultFloat;

                if (double.TryParse(str, out double resultDouble))
                    return (long)resultDouble;
            }

            throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX14300, claimName, jsonElement.ToString(), typeof(long))));
        }
#endif
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
