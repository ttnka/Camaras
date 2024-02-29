using System;
using Microsoft.AspNetCore.Components;

namespace TorneosV2.Pages.Sistema.Mensajes
{
	public class exitosBase : ComponentBase
	{
		[Inject]
		public NavigationManager NM { get; set; } = default!;

		protected override async Task OnInitializedAsync()
		{
			
		}


	}
}

