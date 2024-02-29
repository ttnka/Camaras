using System;
using System.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Radzen;
using Radzen.Blazor;
using TorneosV2.Data;
using TorneosV2.Modelos;

namespace TorneosV2.Pages.Sistema
{
	public class MisDatosBase : ComponentBase
	{
        public const string TBita = "Mis datos!";

        [Inject]
        public IEnviarMail ReenviarMail { get; set; } = default!;
        [Inject]
        public UserManager<IdentityUser> UManager { get; set; } = default!;
        [Inject]
        public Repo<ZConfig, ApplicationDbContext> ZConfigRepo { get; set; } = default!;
        [Inject]
        public Repo<Z100_Org, ApplicationDbContext> OrgRepo { get; set; } = default!;
        [Inject]
        public Repo<Z110_User, ApplicationDbContext> UserRepo { get; set; } = default!;
        [Parameter]
        public EventCallback ActualizaElUser { get; set; }

        public MisDatosClass MDUser { get; set; } = new();
        protected bool Leyendo { get; set; } = false;
        protected bool Editando { get; set; } = false;

        public List<KeyValuePair<int, string>> Niveles { get; set; } =
            new List<KeyValuePair<int, string>>();
        public string Msn { get; set; } = "";

        public RadzenTemplateForm<MisDatosClass>? MDataForm { get; set; } =
                        new RadzenTemplateForm<MisDatosClass>();

        protected bool BotonNuevo { get; set; } = false;
        protected bool Primera { get; set; } = true;

        protected override async Task OnInitializedAsync()
        {
            if (Primera)
            {
                Leer();
                Primera = false;
            }

            //await LeerOrgs();
        }

        protected void Leer()
        {
            if (ElUser == null) return;
            MDUser.Pass = "";
            MDUser.ConfPass = "";
            MDUser.ConfEmail = "";
            MDUser.Email = ElUser.OldEmail;
            MDUser.Nombre = ElUser.Nombre;
            MDUser.Paterno = ElUser.Paterno;
            MDUser.Materno = ElUser.Materno ?? "";

            if (Niveles.Any()) return;
            string[] nTmp = Constantes.Niveles.Split(',');
            for (int i = 0; i < nTmp.Length; i++)
            {
                Niveles.Add(new KeyValuePair<int, string>(i + 1, nTmp[i]));
            }

        }

        protected async Task<ApiRespValor> UpdatePass(MisDatosClass data)
        {
            ApiRespValor resp = new() { Exito = false };
            try
            {
                var userTmp = await UManager.FindByEmailAsync(data.Email);
                if (userTmp == null) return resp;

                var code = await UManager.GeneratePasswordResetTokenAsync(userTmp);
                //code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                var cambio = await UManager.ResetPasswordAsync(userTmp, code, data.Pass);
                if (cambio.Succeeded)
                {
                    Z190_Bitacora bitaT = new(ElUser.UserId, $"Se actualizo el password del usuario", ElUser.OrgId);
                    bitaT.OrgAdd(ElUser.Org);
                    await BitacoraAll(bitaT);
                }
                else
                {
                    resp.MsnError.Add($"No fue posible actualiza password, ");
                    foreach(var e in cambio.Errors)
                    {
                        resp.MsnError.Add($"{e}");
                    }
                }
                
                resp.Exito = cambio.Succeeded;
            }
            catch (Exception ex)
            {
                Z192_Logs logT = new(ElUser.UserId, $"No fue posible actualizar el password del usuario, {ex}", false);
                await LogAll(logT);
            }
            return resp;
        }


        protected void CheckPass()
        {

            Msn = "";
            if (MDUser.Email.Length < 5 ||  MDUser.Nombre.Length < 1 || MDUser.Paterno.Length < 1 )
                return;
            
            if (MDUser.Pass.Length > 1 || ElUser.Estado == 3)
            {
                string[] Prohibido = { "Password", "contraseña", "123", "aaa" };
                bool IsMin = false;
                bool IsMay = false;
                bool IsNum = false;
                bool HasRep = false;

                if (MDUser.Pass.Length < 2 || MDUser.ConfPass.Length < 2) return;

                
                foreach (char c in MDUser.Pass)
                {
                    IsMin = char.IsLower(c) ? true : IsMin;
                    IsMay = char.IsUpper(c) ? true : IsMay;
                    IsNum = char.IsNumber(c) ? true : IsNum;
                    HasRep = MDUser.Pass.Count(x => x == c) > 2 ? true : HasRep;
                }

                Msn = MDUser.Pass.Length < 6 ? "El Password requiere al menos 6 caracteres! " : Msn;
                Msn += !IsMin ? "El Password requiere almenos una minuscula! " : Msn;
                Msn += !IsMay ? "El Password requiere almenos una mayuscula! " : Msn;
                Msn += !IsNum ? "El Password requiere almenos un numero! " : Msn;
                Msn += HasRep ? "El Password no puede tener caracteres repetidos, 3 veces! " : Msn;
                Msn += Prohibido.Contains(MDUser.Pass.ToLower()) ? "El Password no es una palabra aceptable! " : Msn;

                Msn = Msn == "" ? "Ok" : Msn;
            }
            else
            {
                Msn = "Ok";
            }


            Msn = (Msn == "Ok" && MDUser.Email.Length > 5 && MDUser.Nombre.Length > 1 && MDUser.Paterno.Length > 1) ?
                 Msn : "Falta informacion en tu formulario!";
            BotonNuevo = Msn == "Ok" ? false : true; 
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
        public Z190_Bitacora LastBita { get; set; } = new(userId: "", desc: "", orgId: "");
        public Z192_Logs LastLog { get; set; } = new(userId: "Sistema", desc: "", sistema: false);
        public async Task BitacoraAll(Z190_Bitacora bita)
        {
            if (bita.BitacoraId != LastBita.BitacoraId)
            {
                LastBita = bita;
                await BitaRepo.Insert(bita);
            }
        }

        public async Task LogAll(Z192_Logs log)
        {
            if (log.LogId != LastLog.LogId)
            {
                LastLog = log;
                await LogRepo.Insert(log);
            }

        }
        #endregion

        public class MisDatosClass
        {
            public string Email { get; set; } = "";
            public string ConfEmail { get; set; } = "";
            public string Nombre { get; set; } = "";
            public string Paterno { get; set; } = "";
            public string Materno { get; set; } = "";
            public string Pass { get; set; } = "";
            public string ConfPass { get; set; } = "";
        }

    }
}

