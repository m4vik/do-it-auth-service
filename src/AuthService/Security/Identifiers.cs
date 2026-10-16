using System.Net.Mail;
using AuthService.Features;
using PhoneNumbers;

namespace AuthService.Security;

public static class Identifiers
{
    public static (string Type, string Value) Normalize(string type, string value)
    {
        type = type.Trim().ToLowerInvariant();
        value = value.Trim();
        if (type == "email" && MailAddress.TryCreate(value, out var address)
            && address.Address == value && value.Length <= 254 && address.Host.Contains('.'))
            return (type, value.ToLowerInvariant());

        if (type == "phone" && value.StartsWith('+'))
        {
            var phones = PhoneNumberUtil.GetInstance();
            try
            {
                var number = phones.Parse(value, null);
                if (phones.IsValidNumber(number) && !number.HasExtension)
                    return (type, phones.Format(number, PhoneNumberFormat.E164));
            }
            catch (NumberParseException) { }
        }
        throw new ApiException(400, "invalid_identifier", "Provide a valid email or an international phone number.");
    }
}
