// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if !NET45
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Microsoft.IdentityModel.Tokens
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public static class JsonSerializerHelper
    {
        public static bool AdvancePastStartObject(ref Utf8JsonReader reader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType == JsonTokenType.StartObject)
                return reader.Read();

            return false;
        }

        public static void CheckForStartArray(ref Utf8JsonReader reader, object caller, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != JsonTokenType.StartArray)
                throw new JsonException($"{caller}, expected JsonTokenType of StartArray, found: '{reader.TokenType}'.");

            if (advanceReader)
                reader.Read();
        }

        public static void CheckForStartObject(ref Utf8JsonReader reader, object caller, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != JsonTokenType.StartObject)
                throw new JsonException($"{caller}, expected JsonTokenType of StartObject, found: '{reader.TokenType}'.");

            if (advanceReader)
                reader.Read();
        }

        public static void CheckForTokenType(ref Utf8JsonReader reader, JsonTokenType tokenType, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != tokenType)
                throw new JsonException($"Expected JsonTokenType of '{tokenType}', found: '{reader.TokenType}'.");

            if (advanceReader)
                reader.Read();
        }

        public static void CheckForTokenType(ref Utf8JsonReader reader, object caller, JsonTokenType tokenType, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType !=  tokenType)
                throw new JsonException($"{caller}, expected JsonTokenType of '{tokenType}', found: '{reader.TokenType}'.");

            if (advanceReader)
                reader.Read();
        }

        public static string GetPropertyName(ref Utf8JsonReader reader, object caller, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != JsonTokenType.PropertyName)
                throw new JsonException($"{caller}, expected JsonTokenType of PropertyName, found: '{reader.TokenType}'.");

            if (advanceReader)
            {
                string propertyName = reader.GetString();
                reader.Read();
                return propertyName;
            }

            return reader.GetString();
        }

        public static string GetPropertyName(ref Utf8JsonReader reader, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != JsonTokenType.PropertyName)
                throw new JsonException($"Expected JsonTokenType of PropertyName, found: '{reader.TokenType}'.");

            if (advanceReader)
            {
                string propertyName = reader.GetString();
                reader.Read();
                return propertyName;
            }

            return reader.GetString();
        }

        public static Utf8JsonWriter GetUtf8JsonWriter(Stream stream)
        {
#if DEBUG
            return new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true , SkipValidation = true });
#else
            return new Utf8JsonWriter(stream);
#endif
        }

        public static string CheckForPropertyName(ref Utf8JsonReader reader, object caller, string requiredPropertyName, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != JsonTokenType.PropertyName)
                throw new JsonException($"{caller}, expected JsonTokenType of PropertyName, found: '{reader.TokenType}'.");

            string propertyName = reader.GetString();
            if (propertyName != requiredPropertyName)
                throw new JsonException($"{caller}, expected PropertyName to be '{requiredPropertyName}, found: '{propertyName}'.");

            if (advanceReader)
                reader.Read();

            return propertyName;
        }

        public static string GetPropertyStringValue(ref Utf8JsonReader reader, object caller, string requiredPropertyName, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != JsonTokenType.PropertyName)
                throw new JsonException($"{caller}, expected JsonTokenType of PropertyName, found: '{reader.TokenType}'.");

            string propertyName = reader.GetString();
            if (propertyName != requiredPropertyName)
                throw new JsonException($"{caller}, expected PropertyName to be '{requiredPropertyName}, found: '{propertyName}'.");

            reader.Read();

            if (reader.TokenType != JsonTokenType.String)
                throw new JsonException($"{caller}, expected PropertyValue to be a string for Property: '{requiredPropertyName}', found: '{reader.TokenType}'.");

            string propertyValue = reader.GetString();
            if (advanceReader)
                reader.Read();

            return propertyValue;
        }

        public static bool IsEndObject(ref Utf8JsonReader reader, bool advanceReader)
        {
            if (reader.TokenType != JsonTokenType.EndObject)
                return false;

            if (advanceReader)
                reader.Read();

            return true;
        }

        public static bool IsEndArray(ref Utf8JsonReader reader, bool advanceReader)
        {
            if (reader.TokenType != JsonTokenType.EndArray)
                return false;

            if (advanceReader)
                reader.Read();

            return true;
        }

        public static ICollection<string> ReadStrings(ref Utf8JsonReader reader, ICollection<string> strings)
        {
            _ = strings ?? throw new ArgumentNullException(nameof(strings));

            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != JsonTokenType.StartArray)
                throw new JsonException();

            reader.Read();
            do
            {
                if (reader.TokenType == JsonTokenType.EndArray)
                    break;

                if (reader.TokenType != JsonTokenType.String)
                    throw new JsonException();

                strings.Add(reader.GetString());

            } while (reader.Read());

            // EndArray
            reader.Read();

            return strings;
        }

        public static bool ReadBoolean(ref Utf8JsonReader reader)
        {
            if (reader.TokenType == JsonTokenType.True || reader.TokenType == JsonTokenType.False)
                return reader.GetBoolean();

            throw new JsonException();
        }

        public static double ReadDouble(ref Utf8JsonReader reader)
        {
            if (reader.TokenType != JsonTokenType.Number)
                throw new JsonException();

            return reader.GetDouble();
        }

        public static string ReadString(ref Utf8JsonReader reader)
        {
            if (reader.TokenType != JsonTokenType.String)
                throw new JsonException();

            return reader.GetString();
        }

        public static ICollection<string> ReadStrings(ref Utf8JsonReader reader)
        {
            IList<string> strings = new List<string>();
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != JsonTokenType.StartArray)
                throw new JsonException();

            do
            {
                if (reader.TokenType != JsonTokenType.String)
                    throw new JsonException();

                strings.Add(reader.GetString());

                if (reader.TokenType == JsonTokenType.EndArray)
                    break;

            } while (reader.Read());

            // EndArray
            reader.Read();

            return strings;
        }

        public static void WriteStrings(ref Utf8JsonWriter writer, string propertyName, ICollection<string> strings)
        {
            _ = writer ?? throw new ArgumentNullException(nameof(writer));
            _ = strings ?? throw new ArgumentNullException(nameof(strings));
            if (string.IsNullOrEmpty(propertyName))
                throw new ArgumentNullException(nameof(propertyName));

            writer.WritePropertyName(propertyName);
            writer.WriteStartArray();
            foreach (string str in strings)
                writer.WriteStringValue(str);

            writer.WriteEndArray();
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
#endif // !NET45
