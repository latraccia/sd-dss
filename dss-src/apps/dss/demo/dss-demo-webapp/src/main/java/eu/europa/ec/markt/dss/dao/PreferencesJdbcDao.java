/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.dao;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Required;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

import eu.europa.ec.markt.dss.model.Preference;
import eu.europa.ec.markt.dss.model.PreferenceKey;

/**
 * 
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class PreferencesJdbcDao implements PreferencesDao {

    /**
     * 
     * @see RowMapper
     * 
     *      <p>
     *      DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
     */
    private class PreferenceRowMapper implements RowMapper<Preference> {
        /*
         * (non-Javadoc)
         * 
         * @see org.springframework.jdbc.core.RowMapper#mapRow(java.sql.ResultSet, int)
         */
        @Override
        public Preference mapRow(ResultSet rs, int row) throws SQLException {
            final Preference preference = new Preference();
            preference.setKey(rs.getString(COLUMN_KEY));
            preference.setValue(rs.getString(COLUMN_VALUE));
            return preference;
        }
    }

    private static final String TABLE_NAME = "PREFERENCES";
    private static final String COLUMN_KEY = "PREF_KEY";
    private static final String COLUMN_VALUE = "PREF_VALUE";

    /**
     * @see JdbcTemplate
     */
    private JdbcTemplate jdbcTemplate;
    /**
     * @see NamedParameterJdbcTemplate
     */
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.dao.GenericDao#get(java.lang.Object)
     */
    @Override
    public Preference get(PreferenceKey id) {
        final String query = "select * from " + TABLE_NAME + " where " + COLUMN_KEY + " = :key";
        final SqlParameterSource namedParameters = new MapSqlParameterSource("key", id);
        return namedParameterJdbcTemplate.queryForObject(query, namedParameters, new PreferenceRowMapper());
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.dao.GenericDao#getAll()
     */
    @Override
    public List<Preference> getAll() {
        final String query = "select * from " + TABLE_NAME;
        return jdbcTemplate.query(query, new PreferenceRowMapper());
    }

    /**
     * Set the datasource
     * 
     * @param dataSource The datasource
     */
    @Required
    public void setDataSource(final DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        this.namedParameterJdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.dao.GenericDao#update(java.lang.Object)
     */
    @Override
    public void update(Preference entity) {
        final String query = "update " + TABLE_NAME + " set " + COLUMN_VALUE + " = :value where " + COLUMN_KEY
                + " = :key";
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("key", entity.getKey());
        parameters.put("value", entity.getValue());
        final SqlParameterSource namedParameters = new MapSqlParameterSource(parameters);
        namedParameterJdbcTemplate.update(query, namedParameters);
    }

}
