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

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Identity.Web.TokenCacheProviders.InMemory;
using Sidub.Platform.Authentication.Handlers;

#endregion

namespace Sidub.Platform.Authentication
{

    /// <summary>
    /// Static helper class providing IServiceCollection extensions.
    /// </summary>
    public static class ServiceCollectionExtensions
    {

        #region Extension methods

        /// <summary>
        /// Adds Sidub authentication for HTTP.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add the authentication services to.</param>
        /// <returns>The modified <see cref="IServiceCollection"/>.</returns>
        public static IServiceCollection AddSidubAuthenticationForHttp(
            this IServiceCollection services)
        {
            services.AddSidubAuthentication();
            services.AddInMemoryTokenCaches();
            services.TryAddEnumerable(ServiceDescriptor.Transient<IAuthenticationHandler, FlurlClientAuthenticationHandler>());

            return services;
        }

        #endregion

    }
}
