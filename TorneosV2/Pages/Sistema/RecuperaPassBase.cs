using System;
using System.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Radzen;
using Radzen.Blazor;
using TorneosV2.Data;
using TorneosV2.Modelos;
using static TorneosV2.Pages.Sistema.EntradaBase;

namespace TorneosV2.Pages.Sistema
{
	public class RecuperaPassBase : ComponentBase 
	{
        public const string TBita = "Recupera tu password";
        [Inject]
        public Repo<Z110_User, ApplicationDbContext> UserRepo { get; set; } = default!;
        [Inject]
        public SignInManager<IdentityUser> SManager { get; set; } = default!;
        [Inject]
        public UserManager<IdentityUser> UManager { get; set; } = default!;
        [Inject]
        public IEnviarMail SendMail { get; set; } = default!;


        public Z110_User Usuario { get; set; } = default!;
        public MailInfo RecuperaData { get; set; } = new();
        public RadzenTemplateForm<MailInfo>? RecuperaForm { get; set; } = new RadzenTemplateForm<MailInfo>();


        protected async Task RecuperarTask()
        {
            string avance = "";

            try
            {
                var user = await UManager.FindByEmailAsync(RecuperaData.EMail);

                if (user != null)
                {
                    avance += "Se encontro el usuario por mail, ";
                    Usuario = await UserRepo.GetById(user!.Id);

                    if (Usuario == null) return;

                    var code = await UManager.GeneratePasswordResetTokenAsync(user!);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                    var userId = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(user.Id));
                    var t = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()));
                    var backUrl = NM.ToAbsoluteUri($"/cambiopass/{code}/{user.Id}/{t}");

                    avance += $"se genero codigo y pagina de recuperacion {backUrl}, ";
                    MailCampos mCs = new()
                    {
                        Titulo = $"Tenemos una solicitud de cambio de password dominio {Constantes.ElDominio} con tu e-mail!",
                        Cuerpo = $"Hola {Usuario.Nombre}, <br />Soy el administrador de {Constantes.ElDominio}, y tenemos ",
                    };

                    mCs.Cuerpo += $"una direccion para que cambies tu password: <br />";
                    mCs.Cuerpo += $"recuerda tu password deben ser 6 caracteres ";
                    mCs.Cuerpo += $"utiliza una nueva palabra que contenga una letra mayuscula, una minuscula y un numero, <br />";
                    mCs.Cuerpo += $"<br />Entra a nuestra pagina con esta liga ==>> ";
                    mCs.Cuerpo += $"<a href=\"{backUrl}\"> abre nuestra pagina aqui</a> <== <br />";
                    mCs.Cuerpo += $"si tienes dudas contactanos via Email {Constantes.DeMail01Soporte} <br /> <br />";
                    mCs.Cuerpo += $"Saludos del equipo de {Constantes.ElDominio}";

                    mCs.ParaNombre.Add(Usuario.Completo);
                    mCs.ParaEmail.Add(Usuario.OldEmail);
                    ApiRespuesta<MailCampos> enviado = await SendMail.EnviarMail(mCs, true);
                    avance += enviado.Exito ? "Se envio " : "No fue posible enviar ";
                    avance += $"un mail con la informacion del cambio password! ";

                    Z190_Bitacora bitaT = new(Usuario.UserId, $"Se genero un cambio de password {TBita}", Usuario.OrgId);
                    BitacoraMas(bitaT);
                    await BitacoraWrite();
                }
            }
            catch (Exception ex)
            {
                Z192_Logs logT = new("Sistema_User",
                    $"Error al intentar solicitar un cambio de password {TBita} : {avance} : {ex}", false);
                await LogAll(logT);
            }
            NM.NavigateTo("/", true);
        }


        #region Usuario y Bitacora

        [CascadingParameter(Name = "ElUserAll")]
        public Z110_User ElUser { get; set; } = default!;


        [Inject]
        public Repo<Z190_Bitacora, ApplicationDbContext> BitaRepo { get; set; } = default!;
        [Inject]
        public Repo<Z192_Logs, ApplicationDbContext> LogRepo { get; set; } = default!;

        public MyFunc MyFunc { get; set; } = new MyFunc();
        public NotificationMessage ElMsn(string tipo, string titulo, string mensaje, int duracion)
        {
            NotificationMessage respuesta = new();
            switch (tipo)
            {
                case "Info":
                    respuesta.Severity = NotificationSeverity.Info;
                    break;
                case "Error":
                    respuesta.Severity = NotificationSeverity.Error;
                    break;
                case "Warning":
                    respuesta.Severity = NotificationSeverity.Warning;
                    break;
                default:
                    respuesta.Severity = NotificationSeverity.Success;
                    break;
            }
            respuesta.Summary = titulo;
            respuesta.Detail = mensaje;
            respuesta.Duration = 4000 + duracion;
            return respuesta;
        }
        [Inject]
        public NavigationManager NM { get; set; } = default!;
        public Z192_Logs LastLog { get; set; } = new(userId: "Sistema", desc: "", sistema: false);
        [CascadingParameter(Name = "LasBitacorasAll")]
        public List<Z190_Bitacora> LasBitacoras { get; set; } = new List<Z190_Bitacora>();
        public void BitacoraMas(Z190_Bitacora bita)
        {
            if (!LasBitacoras.Any(b => b.BitacoraId == bita.BitacoraId))
            {

                LasBitacoras.Add(bita);
            }
        }
        public async Task BitacoraWrite()
        {
            foreach (var b in LasBitacoras)
            {
                b.OrgAdd(ElUser.Org);
            }
            await BitaRepo.InsertPlus(LasBitacoras);
            LasBitacoras.Clear();
        }

        public async Task LogAll(Z192_Logs log)
        {
            try
            {
                if (log.LogId != LastLog.LogId)
                {
                    LastLog = log;
                    await LogRepo.Insert(log);
                }
            }
            catch (Exception ex)
            {
                Z192_Logs LogT = new(ElUser.UserId,
                    $"Error al intentar escribir BITACORA, {TBita},{ex}", true);
                await LogAll(LogT);
            }
        }
        #endregion


        public class MailInfo
        {
            public string EMail { get; set; } = "";
        }

    }
}

