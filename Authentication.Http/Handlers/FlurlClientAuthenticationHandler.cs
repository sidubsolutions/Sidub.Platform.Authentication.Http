/*
 * Sidub Platform - Authentication - HTTP
 * Copyright (C) 2024 Sidub Inc.
 * All rights reserved.
 *
 * This file is part of Sidub Platform - Authentication - HTTP (the "Product").
 *
 * The Product is dual-licensed under:
 * 1. The GNU Affero General Public License version 3 (AGPLv3)
 * 2. Sidub Inc.'s Proprietary Software License Agreement (PSLA)
 *
 * You may choose to use, redistribute, and/or modify the Product under
 * the terms of either license.
 *
 * The Product is provided "AS IS" and "AS AVAILABLE," without any
 * warranties or conditions of any kind, either express or implied, including
 * but not limited to implied warranties or conditions of merchantability and
 * fitness for a particular purpose. See the applicable license for more
 * details.
 *
 * See the LICENSE.txt file for detailed license terms and conditions or
 * visit https://sidub.ca/licensing for a copy of the license texts.
 */

#region Imports

using Azure.Core;
using Flurl.Http;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Sidub.Platform.Authentication.Credentials;
using Sidub.Platform.Core;
using Sidub.Platform.Core.Services;

#endregion

namespace Sidub.Platform.Authentication.Handlers
{

    /// <summary>
    /// Handles authentication for HTTP (FlurlClient) requests.
    /// </summary>
    public class FlurlClientAuthenticationHandler : IAuthenticationHandler<IFlurlClient>
    {

        #region Member variables

        private readonly IServiceRegistry _serviceRegistry;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="FlurlClientAuthenticationHandler"/> class.
        /// </summary>
        /// <param name="serviceRegistry">The service registry.</param>
        public FlurlClientAuthenticationHandler(IServiceRegistry serviceRegistry)
        {
            _serviceRegistry = serviceRegistry;
            //_tokenAcquisition = tokenAcquisition;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Handles the authentication for the FlurlClient request.
        /// </summary>
        /// <param name="ServiceReferenceContext">The service reference context.</param>
        /// <param name="request">The FlurlClient request.</param>
        /// <returns>The authenticated FlurlClient request.</returns>
        public IFlurlClient Handle(ServiceReference ServiceReferenceContext, IFlurlClient request)
        {
            // check if authentication exists for given ServiceReference...
            var credential = _serviceRegistry.GetMetadata<IClientCredential>(ServiceReferenceContext).SingleOrDefault();

            // if no credentials exist, exit...
            if (credential is null)
                return request;

            // handle credentials based on type...
            switch (credential)
            {
                case ClientSecretCredential clientSecret:
                    request.BeforeCall(async (t) =>
                    {
                        var confidentialClientApplication = ConfidentialClientApplicationBuilder
                            .Create(clientSecret.ClientId)
                            .WithTenantId(clientSecret.TenantId)
                            .WithClientSecret(clientSecret.Secret)
                            .Build();

                        // direct the client to use an in-memory token cache...
                        confidentialClientApplication.AddInMemoryTokenCache();

                        var url = clientSecret.Scope
                            ?? new Flurl.Url(request.BaseUrl).Root + "/.default";

                        var bearer = await confidentialClientApplication.AcquireTokenForClient(new[] { url.ToString() }).ExecuteAsync();
                        t.Request.Headers.AddOrReplace("Authorization", "Bearer " + bearer.AccessToken);

                    });

                    return request;

                case UserTokenCredential userTokenAcquisition:
                    request.BeforeCall(async (t) =>
                    {
                        ITokenAcquisition tokenAcquisition = userTokenAcquisition.TokenAcquisition;
                        var scope = userTokenAcquisition.Scope;

                        var bearer = await tokenAcquisition.GetAccessTokenForUserAsync(new[] { scope }, null, user: userTokenAcquisition.ClaimsPrincipal);
                        t.Request.Headers.AddOrReplace("Authorization", "Bearer " + bearer);
                    });

                    return request;

                case ServiceTokenCredential serviceCredential:
                    request.BeforeCall(async (t) =>
                    {
                        var opts = new TokenRequestContext(serviceCredential.Scopes);
                        var bearer = await serviceCredential.Credential.GetTokenAsync(opts, CancellationToken.None);

                        t.Request.Headers.AddOrReplace("Authorization", "Bearer " + bearer.Token);
                    });

                    return request;

                case FunctionKeyCredential functionKeyCredential:
                    request.BeforeCall((t) =>
                    {
                        t.Request.Headers.AddOrReplace("x-functions-key", functionKeyCredential.FunctionKey);
                    });

                    return request;


            }

            throw new Exception($"Unhandled credential type '{credential.GetType().Name}' encountered in authentication handler.");
        }

        #endregion

    }

}
