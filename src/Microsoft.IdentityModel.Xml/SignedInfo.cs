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
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class SignedInfo
    {
        readonly ExclusiveCanonicalizationTransform _exclusiveCanonicalizationTransform = new ExclusiveCanonicalizationTransform(true);
        ElementWithAlgorithmAttribute _signatureMethodElement = new ElementWithAlgorithmAttribute(XmlSignatureConstants.Elements.SignatureMethod);
        MemoryStream _bufferedStream;
        string _defaultNamespace = string.Empty;

        public SignedInfo()
        {
        }

        internal MemoryStream CanonicalStream { get; set; }

        protected Dictionary<string, string> Context { get; set; }

        protected string Prefix { get; set; } = XmlSignatureConstants.Prefix;

        public Reference Reference { get; set; }

        public string CanonicalizationMethod
        {
            get { return _exclusiveCanonicalizationTransform.Algorithm; }
            set
            {
                if (value != _exclusiveCanonicalizationTransform.Algorithm)
                {
                    throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedTransformAlgorithm"));
                }
            }
        }

        public bool HasId
        {
            get { return true; }
        }

        public string Id { get; set; }

        public string SignatureAlgorithm { get; set; }

        internal void ComputeHash(HashAlgorithm algorithm)
        {
            if ((CanonicalizationMethod != SecurityAlgorithms.ExclusiveC14n) && (CanonicalizationMethod != SecurityAlgorithms.ExclusiveC14nWithComments))
                throw XmlUtil.LogReadException(LogMessages.IDX21100, CanonicalizationMethod, SecurityAlgorithms.ExclusiveC14n, SecurityAlgorithms.ExclusiveC14nWithComments);

            var hashStream = new HashStream(algorithm);
            ComputeHash(hashStream);
            hashStream.FlushHash();
        }

        internal virtual void ComputeHash(HashStream hashStream)
        {
            GetCanonicalBytes(hashStream);
        }

        internal virtual void GetCanonicalBytes(Stream stream)
        {
            if (CanonicalStream != null)
            {
                CanonicalStream.WriteTo(stream);
            }
            else
            {
                _bufferedStream.Position = 0;
                // We are creating a XmlDictionaryReader with a hard-coded Max XmlDictionaryReaderQuotas. This is a reader that we
                // are creating over an already buffered content. The content was initially read off user provided XmlDictionaryReader
                // with the correct quotas and hence we know the data is valid.
                // Note: signedinfoReader will close _bufferedStream on Dispose.
                using (var signedinfoReader = XmlDictionaryReader.CreateTextReader(_bufferedStream, XmlDictionaryReaderQuotas.Max))
                {
                    signedinfoReader.MoveToContent();
                    using (var bufferingWriter = XmlDictionaryWriter.CreateTextWriter(Stream.Null, Encoding.UTF8, false))
                    {
                        bufferingWriter.WriteStartElement("a", _defaultNamespace);
                        string[] inclusivePrefix = GetInclusivePrefixes();
                        for (int i = 0; i < inclusivePrefix.Length; ++i)
                        {
                            string ns = GetNamespaceForInclusivePrefix(inclusivePrefix[i]);
                            if (ns != null)
                            {
                                bufferingWriter.WriteXmlnsAttribute(inclusivePrefix[i], ns);
                            }
                        }
                        bufferingWriter.StartCanonicalization(stream, false, inclusivePrefix);
                        bufferingWriter.WriteNode(signedinfoReader, false);
                        bufferingWriter.EndCanonicalization();
                        bufferingWriter.WriteEndElement();
                    }
                }
            }
        }

        internal virtual void ComputeReferenceDigests()
        {
            if (Reference == null)
                throw LogHelper.LogExceptionMessage(new CryptographicException("AtLeastOneReferenceRequired"));

            Reference.ComputeAndSetDigest();
        }

        internal virtual void EnsureReferenceVerified()
        {
            if (Reference == null)
                throw LogHelper.LogArgumentNullException(nameof(Reference));

            if (!Reference.Verified)
                throw LogHelper.LogExceptionMessage(new CryptographicException(LogMessages.IDX21201, Reference.Uri));
        }

        protected string[] GetInclusivePrefixes()
        {
            return _exclusiveCanonicalizationTransform.GetInclusivePrefixes();
        }

        protected virtual string GetNamespaceForInclusivePrefix(string prefix)
        {
            if (Context == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException());

            if (prefix == null)
                throw LogHelper.LogArgumentNullException(nameof(prefix));

            return Context[prefix];
        }

        public virtual void ReadFrom(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace, false);

            _defaultNamespace = reader.LookupNamespace(string.Empty);
            _bufferedStream = new MemoryStream();
            var settings = new XmlWriterSettings
            {
                Encoding = Encoding.UTF8,
                NewLineHandling = NewLineHandling.None
            };

            using (XmlWriter bufferWriter = XmlTextWriter.Create(_bufferedStream, settings))
            {
                bufferWriter.WriteNode(reader, true);
                bufferWriter.Flush();
            }

            _bufferedStream.Position = 0;

            //
            // We are creating a XmlDictionaryReader with a hard-coded Max XmlDictionaryReaderQuotas. This is a reader that we
            // are creating over an already buffered content. The content was initially read off user provided XmlDictionaryReader
            // with the correct quotas and hence we know the data is valid.
            // Note: effectiveReader will close _bufferedStream on Dispose.
            //
            using (var canonicalizingReader = XmlDictionaryReader.CreateTextReader(_bufferedStream, XmlDictionaryReaderQuotas.Max))
            {
                CanonicalStream = new MemoryStream();
                canonicalizingReader.StartCanonicalization(CanonicalStream, false, null);
                canonicalizingReader.MoveToStartElement(XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace);
                Prefix = canonicalizingReader.Prefix;
                Id = canonicalizingReader.GetAttribute(XmlSignatureConstants.Attributes.Id, null);
                canonicalizingReader.Read();
                _exclusiveCanonicalizationTransform.ReadFrom(canonicalizingReader, false);
                _signatureMethodElement.ReadFrom(canonicalizingReader);
                SignatureAlgorithm = _signatureMethodElement.Algorithm;

                XmlUtil.CheckReaderOnEntry(canonicalizingReader, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace, false);
                Reference = new Reference();
                Reference.ReadFrom(canonicalizingReader);

                if (canonicalizingReader.IsStartElement(XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace))
                    throw XmlUtil.LogReadException(LogMessages.IDX21020);

                canonicalizingReader.ReadEndElement();
                canonicalizingReader.EndCanonicalization();
            }

            string[] inclusivePrefixes = GetInclusivePrefixes();
            if (inclusivePrefixes != null)
            {
                // We cannot use the canonicalized stream when inclusive prefixes are specified.
                CanonicalStream = null;
                Context = new Dictionary<string, string>(inclusivePrefixes.Length);
                for (int i = 0; i < inclusivePrefixes.Length; i++)
                {
                    Context.Add(inclusivePrefixes[i], reader.LookupNamespace(inclusivePrefixes[i]));
                }
            }
        }

        public virtual void WriteTo(XmlDictionaryWriter writer)
        {
            if (writer == null)
                LogHelper.LogArgumentNullException(nameof(writer));

            // <SignedInfo>
            writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace);

            // @Id
            if (Id != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, Id);

            WriteCanonicalizationMethod(writer);
            WriteSignatureMethod(writer);
            if (Reference != null)
                Reference.WriteTo(writer);

            // </SignedInfo>
            writer.WriteEndElement();
        }

        protected void WriteCanonicalizationMethod(XmlDictionaryWriter writer)
        {
            _exclusiveCanonicalizationTransform.WriteTo(writer);
        }

        protected void WriteSignatureMethod(XmlDictionaryWriter writer)
        {
            _signatureMethodElement.WriteTo(writer);
        }
    }
}