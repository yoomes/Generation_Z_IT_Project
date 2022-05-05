/*
 * Copyright (c) 2020. University of Applied Sciences and Arts Northwestern Switzerland FHNW.
 * All rights reserved.
 */

package ch.fhnw.acrm.data.domain;



import javax.persistence.*;


@Entity
public class Product {

	@Id
	@GeneratedValue
	private Long id;

	// TODO: Define variables

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}
}
