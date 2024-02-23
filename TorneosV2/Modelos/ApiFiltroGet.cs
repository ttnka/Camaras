﻿using System;
using System.Linq.Expressions;

namespace TorneosV2.Modelos
{
    public interface ApiFiltroGet<TEntity> : IRepo<TEntity> where TEntity : class
    {
        Task<IEnumerable<TEntity>> Get(
            Expression<Func<TEntity, bool>> filtro = null,
            Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>> orderby = null,
            string propiedades = "");
    }
}

