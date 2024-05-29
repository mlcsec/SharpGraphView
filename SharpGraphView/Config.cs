using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SharpGraphView
{
    class Config
    {
        public static string accessToken = "";
        public static string searchString = "";
        public static string id = "";
        public static string select = "";
        public static string entity = "";
        public static string query = "";
        public static string tenant = "";
        public static string key = "";
        public static string domain = "";
        public static X509Certificate2 cert;

        public static string[] properties = {
                "aboutMe",
                "accountEnabled",
                "ageGroup",
                "assignedLicenses",
                "assignedPlans",
                "birthday",
                "businessPhones",
                "city",
                "companyName",
                "consentProvidedForMinor",
                "country",
                "createdDateTime",
                "department",
                "displayName",
                "employeeId",
                "faxNumber",
                "givenName",
                "hireDate",
                "id",
                "imAddresses",
                "interests",
                "isResourceAccount",
                "jobTitle",
                "lastPasswordChangeDateTime",
                "legalAgeGroupClassification",
                "licenseAssignmentStates",
                "mail",
                "mailboxSettings",
                "mailNickname",
                "mobilePhone",
                "mySite",
                "officeLocation",
                "onPremisesDistinguishedName",
                "onPremisesDomainName",
                "onPremisesImmutableId",
                "onPremisesLastSyncDateTime",
                "onPremisesSecurityIdentifier",
                "onPremisesSyncEnabled",
                "onPremisesSamAccountName",
                "onPremisesUserPrincipalName",
                "otherMails",
                "passwordPolicies",
                "passwordProfile",
                "pastProjects",
                "preferredDataLocation",
                "preferredLanguage",
                "preferredName",
                "proxyAddresses",
                "responsibilities",
                "schools",
                "showInAddressList",
                "skills",
                "state",
                "streetAddress",
                "surname",
                "usageLocation",
                "userPrincipalName",
                "userType",
                "webUrl"
            };
    }
}