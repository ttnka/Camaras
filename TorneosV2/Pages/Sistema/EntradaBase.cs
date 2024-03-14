using System;
using System.Text;
using MathNet.Numerics.Distributions;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using NPOI.SS.Formula.Functions;
using Radzen;
using Radzen.Blazor;
using TorneosV2.Data;
using TorneosV2.Modelos;

namespace TorneosV2.Pages.Sistema
{
	public class EntradaBase : ComponentBase
	{
        public const string TBita = "Login Indentificate";
        [Inject]
        public Repo<Z110_User, ApplicationDbContext> UserRepo { get; set; } = default!;
        [Inject]
        public SignInManager<IdentityUser> SManager { get; set; } = default!;
        [Inject]
        public UserManager<IdentityUser> UManager { get; set; } = default!;
        [Inject]
        public IEnviarMail SendMail { get; set; } = default!;
        
        [Parameter]
        public string UrlReturn { get; set; } = "/";

        
        public int Intento { get; set; } = 0;
        public LoginUser NuevoLogin { get; set; } = new();

        public RadzenTemplateForm<LoginUser>? LoginForm { get; set; } = new RadzenTemplateForm<LoginUser>();

        protected async Task<bool> LogInTask(LoginUser data)
        {
            try
            {
                if (Intento > 3) return false; 
                var resultado = await SManager.PasswordSignInAsync(
                              data.Email, data.Pass, data.Recordar, false);

                if (resultado.Succeeded)
                {
                    Intento = 0;
                    return true;
                }
                Intento++;
            }
            catch (Exception ex)
            {
                Z192_Logs logT = new("Sistema_user", $"No fue posible identificarse {TBita} {ex}", false);
                await LogAll(logT);
            }

            return false;
        }

        protected async Task RecuperarTask()
        {
            string avance = "";

            try
            {
                var user = await UManager.FindByEmailAsync(NuevoLogin.Email);

                if (user != null)
                {
                    avance += "Se encontro el usuario por mail, ";
                    ElUser = await UserRepo.GetById(user!.Id);
                    if (ElUser == null) return;

                    var code = await UManager.GeneratePasswordResetTokenAsync(user!);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var callBackUrl = NM.ToAbsoluteUri($"/nuevopass?code={code}");
                    avance += $"se genero codigo y pagina de recuperacion {callBackUrl}, ";
                    MailCampos mCs = new()
                    {
                        Titulo = $"Tenemos una solicitud de cambio de password dominio {Constantes.ElDominio} con tu e-mail!",
                        Cuerpo = $"Hola {ElUser.Nombre}, <br />Soy el administrador de {Constantes.ElDominio}, y tenemos ",
                    };

                    mCs.Cuerpo += $"una direccion para que cambies tu password: <br />";
                    mCs.Cuerpo += $"recuerda tu password deben ser 6 caracteres ";
                    mCs.Cuerpo += $"utiliza una nueva palabra que contenga una letra mayuscula, una minuscula y un numero, <br />";                  
                    mCs.Cuerpo += "Entra a nuestra pagina con esta liga ==>> ";
                    mCs.Cuerpo += $"<a href=\"{Constantes.ElDominio}{callBackUrl}\"> abre nuestra pagina aqui</a> <== <br />";
                    mCs.Cuerpo += $"si tienes dudas contactanos via Email {Constantes.DeMail01Soporte} <br /> <br />";
                    mCs.Cuerpo += $"Saludos del equipo de {Constantes.ElDominio}";

                    mCs.ParaNombre.Add(ElUser.Completo);
                    mCs.ParaEmail.Add(ElUser.OldEmail);
                    ApiRespuesta<MailCampos> enviado = await SendMail.EnviarMail(mCs, true);
                    avance += enviado.Exito ? "Se envio " : "No fue posible enviar ";
                    avance += $"un mail con la informacion del cambio password! ";
                    
                    Z190_Bitacora bitaT = new(ElUser.UserId, $"Se genero un cambio de password {TBita}", ElUser.OrgId);
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

        public class LoginUser
        {
            public string Email { get; set; } = "";
            public string Pass { get; set; } = "";
            public bool Recordar { get; set; } = false;
            
        }

    }
}

