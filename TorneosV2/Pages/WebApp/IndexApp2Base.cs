using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Radzen;
using TorneosV2.Data;
using TorneosV2.Modelos;

namespace TorneosV2.Pages.WebApp
{
	public class IndexApp2Base : ComponentBase 
	{
        public const string TBita = "Index app";

        [Inject]
        public Repo<Z110_User, ApplicationDbContext> UserRepo { get; set; } = default!;

        protected bool Primera { get; set; } = true;
        protected bool Leyendo { get; set; } = false;
        protected bool Editando { get; set; } = false;

        protected override async Task OnInitializedAsync()
        {
            if (Primera)
            {
                await LeerElUser();
                Primera = false;
            }

            //await LeerOrgs();
        }

        public async Task ReLeerElUser()
        {
            ElUser = await UserRepo.GetById(ElUser.UserId);
            NM.NavigateTo(NM.Uri, true);
        }

        #region Usuario y Bitacora

        [CascadingParameter(Name = "ElUserAll")]
        public Z110_User ElUser { get; set; } = default!;
        public Z100_Org LaOrg { get; set; } = default!;

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
            try
            {
                if (bita.BitacoraId != LastBita.BitacoraId)
                {
                    LastBita = bita;
                    await BitaRepo.Insert(bita);
                }
            }
            catch (Exception ex)
            {
                Z192_Logs LogT = new(ElUser.UserId,
                    $"Error al intentar escribir BITACORA, {TBita},{ex}", true);
                await LogAll(LogT);
            }
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


        #region Preguntar USER
        [Inject]
        public UserManager<IdentityUser> UserMger { get; set; } = default!;

        [CascadingParameter]
        public Task<AuthenticationState> AuthStateTask { get; set; } = default!;

        public async Task LeerElUser()
        {
            try
            {
                ClaimsPrincipal user = (await AuthStateTask).User;
                if (user != null && user.Identity != null && user.Identity.IsAuthenticated)
                {
                    string elId = UserMger.GetUserId(user) ?? "Vacio";
                    if (elId == null || elId == "Vacio") NM.NavigateTo("Identity/Account/Login?ReturnUrl=/", true);
                    var resp = await UserRepo.Get(x => x.UserId == elId, propiedades: "Org");
                    //Niveles = "1Registrado,2Proveedor,3Cliente,4Cliente_Admin,5Alija,6Alija_Admin";
                    if (resp == null || !resp.Any())
                    {
                        NM.NavigateTo("Identity/Account/Login?ReturnUrl=/", true);
                    }

                    else
                    {
                        ElUser = resp.FirstOrDefault()!;
                        LaOrg = ElUser.Org;
                        //await Leer();
                    }
                }
                else
                {
                    NM.NavigateTo("Identity/Account/Login?ReturnUrl=/", true);
                }

            }
            catch (Exception ex)
            {
                Z192_Logs LogT = new(ElUser.UserId,
                    $"Error al intentar leer EL USER USUARIO, {TBita},{ex}", true);
                await LogAll(LogT);

            }
        }

        #endregion


    }
}

