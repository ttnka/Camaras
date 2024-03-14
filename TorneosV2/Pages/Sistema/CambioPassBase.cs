
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
using static Org.BouncyCastle.Crypto.Engines.SM2Engine;
using static TorneosV2.Pages.Sistema.EntradaBase;

namespace TorneosV2.Pages.Sistema
{
    public class CambioPassBase : ComponentBase
	{
        public const string TBita = "Cambio de Password";

        [Inject]
        public UserManager<IdentityUser> UManager { get; set; } = default!;
        [Inject]
        public Repo<Z100_Org, ApplicationDbContext> OrgRepo { get; set; } = default!;
        [Inject]
        public Repo<Z110_User, ApplicationDbContext> UserRepo { get; set; } = default!;

        [Parameter]
        public string C { get; set; } = "Vacio";
        [Parameter]
        public string D { get; set; } = "Vacio";
        [Parameter]
        public string T { get; set; } = "Vacio";

        public PassClase PassData { get; set; } = new();
        public Z110_User UserTmp { get; set; } = default!;
        public Z100_Org OrgTmp { get; set; } = default!;
        protected string Msn { get; set; } = "";
        protected bool Primera { get; set; } = true;
        public RadzenTemplateForm<PassClase>? PassForm { get; set; } = new RadzenTemplateForm<PassClase>();

        protected override async Task OnParametersSetAsync()
        {
            await Leer();
        }
                
        protected async Task Leer()
        {
            if (C == null || C == "Vacio" || C.Length < 10 ||
                     D == null || D == "Vacio" || D.Length < 10 ||
                     T == null)
                NM.NavigateTo("/", true);

            string uId = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(D!));
            UserTmp = await UserRepo.GetById(uId);
            if (UserTmp == null) NM.NavigateTo("/", true);
            OrgTmp = await OrgRepo.GetById(UserTmp!.OrgId);
            if (OrgTmp == null) NM.NavigateTo("/", true);
            UserTmp.OrgAdd(OrgTmp!);
            PassData.Email = UserTmp!.OldEmail;

        }

        public async Task PassF(PassClase data)
        {
            try
            {
                var usuario = await UManager.FindByIdAsync(UserTmp.UserId);
                string ElCode = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(C));
                
                var resp = await UManager.ResetPasswordAsync(usuario!, ElCode, data.Pass);
                if (resp.Succeeded)
                {
                    Z190_Bitacora bitT = new(UserTmp.UserId, $"Se cambio de password {TBita}", UserTmp.OrgId);
                    BitacoraMas(bitT);
                    await BitacoraWrite();
                }
                else
                {
                    throw new Exception();
                }
                    NM.NavigateTo("/exitocambiopass", true);
            }
            catch (Exception ex)
            {
                Z192_Logs logT = new("Sistema_User",
                    $"Error al intentar un cambio de password {TBita} : {ex}", false);
                await LogAll(logT);
            }
        }

        protected void CheckPass()
        {
            Msn = "";
            if (PassData.Pass.Length < 3 || PassData.Confirm.Length < 3) return;

            string[] Prohibido = { "password1", "contraseña", "123", "aaa", "dios" };
            bool IsMin = false;
            bool IsMay = false;
            bool IsNum = false;
            bool HasRep = false;

            foreach (char c in PassData.Pass)
            {
                IsMin = char.IsLower(c) ? true : IsMin;
                IsMay = char.IsUpper(c) ? true : IsMay;
                IsNum = char.IsNumber(c) ? true : IsNum;
                HasRep = PassData.Pass.Count(x => x == c) > 2 ? true : HasRep;
            }

            Msn += PassData.Pass.Length < 6 ? "El Password debe ser minimo 6 caracteres!" : Msn;
            Msn += PassData.Pass != PassData.Confirm ? "La confirmacion del password no coincide!" : Msn;
            Msn += !IsMin ? "El Password requiere almenos una minuscula!" : Msn;
            Msn += !IsMay ? "El Password requiere almenos una mayuscula!" : Msn;
            Msn += !IsNum ? "El Password requiere almenos un numero!" : Msn;
            Msn += HasRep ? "El Password no puede tener caracteres repetidos, 3 veces!" : Msn;
            Msn += Prohibido.Contains(PassData.Pass.ToLower()) ? "El Password no es una palabra aceptable" : Msn;
            Msn = Msn == "" ? "Ok" : Msn;
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

        public class PassClase
		{
            public string Email { get; set; } = "";
			public string Pass { get; set; } = "";
			public string Confirm { get; set; } = "";
		}
	}
}

