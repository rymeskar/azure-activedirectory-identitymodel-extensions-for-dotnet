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


using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a generic configuration manager.
    /// </summary>
    public abstract class StandardConfigurationManager
    {
        /// <summary>
        /// Obtains an updated version of the StandardConfiguration if the appropriate refresh interval has passed.
        /// This method may return a cached version of the configuration.
        /// </summary>
        /// <param name="cancel">CancellationToken</param>
        /// <returns>Configuration of type StandardConfiguration.</returns>
        public abstract Task<StandardConfiguration> GetStandardConfigurationAsync(CancellationToken cancel);

        /// <summary>
        /// The most recently retrieved configuration.
        /// </summary>
        public StandardConfiguration CurrentConfiguration { get; set; }

        /// <summary>
        /// The last known good configuration (a configuration retrieved in the past that we were able to successfully validate a token against).
        /// </summary>
        public StandardConfiguration LKGConfiguration { get; set; }

        /// <summary>
        /// Indicates whether the LKG can be used.
        /// </summary>
        public bool UseLKG { get; set; } = false;

        /// <summary>
        /// Indicates whether the current configuration is valid and safe to use.
        /// </summary>
        public bool UseCurrentConfig { get; set; } = false;

        /// <summary>
        /// Sets the current configuration as the LKG.
        /// </summary>
        public void SetLKG()
        {
            LKGConfiguration = CurrentConfiguration;
            LKGConfiguration.IsLKG = true;
        }
    }
}
