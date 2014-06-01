// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.LinkedIn
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class LinkedInAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="LinkedInAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">LinkedIn Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public LinkedInAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "id");
            Profile = new LinkedInFullProfile(user).ToJson();
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the LinkedIn user obtained from the endpoint https://api.linkedin.com/v1/people/~
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the LinkedIn access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the LinkedIn access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the LinkedIn user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>

        /// <summary>
        /// Gets the LinkedIn extra info
        /// </summary>
        public string Profile { get; set; }
        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }

    #region Helpers Custom
    public class LinkedInFullProfile
    {
        #region Constructs
        public LinkedInFullProfile()
        {
            Certifications = new List<string>();
            Educations = new List<LinkedInFullProfileEducation>();
            Courses = new List<string>();
            Positions = new List<LinkedInFullProfilePositions>();
            Skills = new List<string>();
            Projects = new List<LinkedInFullProfileProjects>();
        }

        public class LinkedInFullProfilePositions
        {
            public string Company { get; set; }
            public string Industry { get; set; }
            public string PositionTitle { get; set; }
            public bool IsCurrentCompany { get; set; }
            public string StartDate { get; set; }
            public string EndDate { get; set; }
            public string PositionSummary { get; set; }
        }

        public class LinkedInFullProfileEducation
        {
            public string SchoolName { get; set; }
            public string Degree { get; set; }
            public string FieldofStudy { get; set; }
        }

        public class LinkedInFullProfileProjects
        {
            public string Name { get; set; }
            public string Description { get; set; }
            public string Url { get; set; }
        }

        public LinkedInFullProfile(JObject user)
        {
            try
            {
                LastModified = new DateTime(1970, 1, 1).AddMilliseconds(user.SelectToken("lastModifiedTimestamp").Value<long>());
                Summary = user.SelectToken("summary") != null ?
                     user.SelectToken("summary").Value<string>().Replace("\n", "<br>")
                     : null;
                Interests = user.SelectToken("interests") != null ?
                     user.SelectToken("interests").Value<string>().Replace("\n", "<br>")
                     : null;
                Certifications = user.SelectToken("certifications") != null
                    ? user["certifications"]["values"].Select(x => x.Value<string>("name")).ToList()
                    : null;
                Courses = user.SelectToken("courses") != null
                   ? user["courses"]["values"].Select(x => x.Value<string>("name")).ToList()
                   : null;
                Skills = user.SelectToken("skills") != null
                   ? user["skills"]["values"].Select(x => x["skill"].Value<string>("name")).ToList()
                   : null;
                Positions = user.SelectToken("positions") != null
                     ? user["positions"]["values"].Select(x => new LinkedInFullProfilePositions
                     {
                         Company = x["company"].Value<string>("name"),
                         PositionTitle = x.Value<string>("title"),
                         Industry = x["company"].Value<string>("industry"),
                         PositionSummary = x.SelectToken("summary") != null ? x.Value<string>("summary").Replace("\n", "<br>") : null,
                         IsCurrentCompany = x.Value<bool>("isCurrent"),
                         StartDate = string.Format("{0} - {1}", x["startDate"].Value<string>("month"), x["startDate"].Value<string>("year")),
                         EndDate = x.SelectToken("endDate") != null ? string.Format("{0} - {1}", x["endDate"].Value<string>("month"), x["endDate"].Value<string>("year")) : null,
                     }).ToList()
                     : null;
                Educations = user.SelectToken("educations") != null
                     ? user["educations"]["values"].Select(x => new LinkedInFullProfileEducation
                     {
                         SchoolName = x.Value<string>("schoolName"),
                         Degree = string.Format("{0} {1} - {2}", x.Value<string>("degree"), x["startDate"].Value<string>("year"), x["endDate"].Value<string>("year")),
                         FieldofStudy = x.Value<string>("fieldOfStudy"),
                     }).ToList()
                     : null;
                Projects = user.SelectToken("projects") != null
                    ? user["projects"]["values"].Select(x => new LinkedInFullProfileProjects
                    {
                        Name = x.Value<string>("name"),
                        Description = x.SelectToken("description") != null ? x.Value<string>("description").Replace("\n", "<br>") : null,
                        Url = x.SelectToken("url") != null ? x.Value<string>("url") : null,
                    }).ToList()
                    : null;
            }
            catch (Exception)
            {
                Certifications = new List<string>();
                Educations = new List<LinkedInFullProfileEducation>();
                Courses = new List<string>();
                Positions = new List<LinkedInFullProfilePositions>();
                Skills = new List<string>();
            }
        }
        #endregion

        public DateTime LastModified { get; set; }
        public String Summary { get; set; }
        public List<string> Certifications { get; set; }
        public List<string> Courses { get; set; }
        public List<LinkedInFullProfileEducation> Educations { get; set; }
        public string Interests { get; set; }
        public List<LinkedInFullProfilePositions> Positions { get; set; }
        public List<LinkedInFullProfileProjects> Projects { get; set; }
        public List<string> Skills { get; set; }

        #region Methods
        public string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this);
        }
        #endregion
    }

   
    #endregion
}
