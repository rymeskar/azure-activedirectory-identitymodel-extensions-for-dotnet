// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if !NET45

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Json;

using System.Text.Json;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    internal class JsonClaimSet
    {
        IList<Claim> _claims;

        private static Type _typeofDateTime = typeof(DateTime);
        public JsonClaimSet()
        {
            RootElement = new JsonElement();
        }

        public JsonClaimSet(byte[] jsonBytes)
        {
            RootElement = JsonDocument.Parse(jsonBytes).RootElement;
        }

        public JsonClaimSet(string json)
        {
            RootElement = JsonDocument.Parse(json).RootElement;
        }

        public bool TryGetValue(string claimName, out JsonElement json)
        {
            return RootElement.TryGetProperty(claimName, out json);
        }

        public JsonElement RootElement { get; }

        // TODO - use lazy.
        internal IList<Claim> Claims(string issuer)
        {
            if (_claims != null)
                return _claims;

            _claims = new List<Claim>();
            foreach (JsonProperty property in RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.Array)
                    foreach (JsonElement jsonElement in property.Value.EnumerateArray())
                       _claims.Add(CreateClaimFromJsonElement(property.Name, jsonElement, issuer));
                else
                    _claims.Add(CreateClaimFromJsonElement(property.Name, property.Value, issuer));
            }

            return _claims;
        }

        private static Claim CreateClaimFromJsonElement(string key, JsonElement jsonElement, string issuer)
        {
            // Json.net recognized DateTime by default.
            if (jsonElement.ValueKind == JsonValueKind.String)
            {
                if (jsonElement.TryGetDateTime(out DateTime dateTimeValue))
                    return new Claim(key, dateTimeValue.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture), ClaimValueTypes.DateTime, issuer, issuer);
                else
                    return new Claim(key, jsonElement.ToString(), ClaimValueTypes.String, issuer, issuer);
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
                if (jsonElement.TryGetInt64(out long longValue))
                    return longValue;
                else if (jsonElement.TryGetInt32(out int intValue))
                    return intValue;
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

        internal Claim GetClaim(string key, string issuer)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (!RootElement.TryGetProperty(key, out JsonElement jsonElement))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14304, key)));

            return CreateClaimFromJsonElement(key, jsonElement, issuer);
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

            return objType.ToString();
        }

        internal string GetStringValue(string key)
        {
            if (RootElement.TryGetProperty(key, out JsonElement jsonElement) && jsonElement.ValueKind == JsonValueKind.String)
                return jsonElement.GetString();
            return string.Empty;
        }

        internal DateTime GetDateTime(string key)
        {
            if (!RootElement.TryGetProperty(key, out JsonElement jsonElement))
                return DateTime.MinValue;

            return EpochTime.DateTime(Convert.ToInt64(Math.Truncate(Convert.ToDouble(ParseTimeValue(key, jsonElement), CultureInfo.InvariantCulture))));
        }

        public T GetValue<T>(string key)
        {
            return GetValueInternal<T>(key, true, out bool _);
        }

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
                    {
                        found = false;
                        value = default;
                    }
                }
                else
                {
                    if (typeof(T) == typeof(JObject))
                    {
                        string json = jsonElement.ToString();
                        return (T)(object)(JObject.Parse(json));
                    }

                    if (typeof(T) == typeof(JArray))
                    {
                        string json = jsonElement.ToString();
                        return (T)(object)(JArray.Parse(json));
                    }

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
                            value = System.Text.Json.JsonSerializer.Deserialize<T>(jsonElement.GetRawText());
                    }
                    else if (typeof(T) == typeof(string))
                    {
                        value = (T)(jsonElement.ToString() as object);
                    }
                    else
                    {
                        value = System.Text.Json.JsonSerializer.Deserialize<T>(jsonElement.GetRawText());
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

        internal bool TryGetClaim(string key, string issuer, out Claim claim)
        {
            if (!RootElement.TryGetProperty(key, out JsonElement jsonElement))
            {
                claim = null;
                return false;
            }

            claim = CreateClaimFromJsonElement(key, jsonElement, issuer);
            return true;
        }

        public bool TryGetValue<T>(string key, out T value)
        {
            value = GetValueInternal<T>(key, false, out bool found);
            return found;
        }

        internal bool HasClaim(string claimName)
        {
            return RootElement.TryGetProperty(claimName, out _);
        }

        private static long ParseTimeValue(string claimName, JsonElement jsonElement)
        {
            if (jsonElement.ValueKind == JsonValueKind.Number)
            {
                if (jsonElement.TryGetInt64(out long retValLong))
                    return retValLong;

                if (jsonElement.TryGetDouble(out double retValDouble))
                    return (long)retValDouble;

                if (jsonElement.TryGetInt32(out int retValInt))
                    return retValInt;

                if (jsonElement.TryGetDecimal(out decimal retValDecimal))
                    return (long)retValDecimal;
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
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}

#endif
